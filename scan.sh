#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="${OUTPUT_ROOT:-/output}"
TARGETS_FILE="${TARGETS_FILE:-/targets/targets.txt}"

SCAN_TYPE="${SCAN_TYPE:-s}"
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-1000}"
NAABU_PORTS="${NAABU_PORTS:-}"
NAABU_RATE="${NAABU_RATE:-1000}"
NAABU_CONCURRENCY="${NAABU_CONCURRENCY:-25}"

NMAP_ARGS="${NMAP_ARGS:--sV -Pn -T3}"

NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_RATE="${NUCLEI_RATE:-150}"
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-25}"
NUCLEI_TAGS="${NUCLEI_TAGS:-}"
NUCLEI_UPDATE="${NUCLEI_UPDATE:-false}"

SKIP_NMAP="${SKIP_NMAP:-false}"
SKIP_NUCLEI="${SKIP_NUCLEI:-false}"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

# grep -c '' rather than wc -l: counts a final line that has no trailing newline.
count() { [ -s "$1" ] && grep -c '' "$1" || printf '0'; }

# Callers (the web UI) may pin RUN_ID so they know the output path up front.
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d-%H%M%S)}"
RUN_DIR="${OUTPUT_ROOT}/scan-${RUN_ID}"
mkdir -p "$RUN_DIR/nmap"

RESOLVED_TARGETS="$RUN_DIR/targets.txt"

if [ "$#" -gt 0 ]; then
    printf '%s\n' "$@" > "$RESOLVED_TARGETS"
    log "targets: ${#} from command line"
elif [ -n "${TARGET:-}" ]; then
    printf '%s' "$TARGET" | tr ',;[:space:]' '\n' | sed '/^$/d' > "$RESOLVED_TARGETS"
    log "targets: $(count "$RESOLVED_TARGETS") from TARGET env var"
elif [ -f "$TARGETS_FILE" ]; then
    sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$TARGETS_FILE" | sed '/^$/d' > "$RESOLVED_TARGETS"
    log "targets: $(count "$RESOLVED_TARGETS") from $TARGETS_FILE"
else
    die "No targets. Set TARGET=<host>, mount a file at $TARGETS_FILE, or pass targets as arguments."
fi

[ -s "$RESOLVED_TARGETS" ] || die "Target list resolved to zero entries."

log "run directory: $RUN_DIR"

# ---------------------------------------------------------------- naabu

NAABU_JSON="$RUN_DIR/naabu.json"
naabu_args=(
    -list "$RESOLVED_TARGETS"
    -json
    -o "$NAABU_JSON"
    -silent
    -rate "$NAABU_RATE"
    -c "$NAABU_CONCURRENCY"
    -scan-type "$SCAN_TYPE"
)
if [ -n "$NAABU_PORTS" ]; then
    naabu_args+=( -p "$NAABU_PORTS" )
else
    naabu_args+=( -top-ports "$NAABU_TOP_PORTS" )
fi

log "stage 1/3: naabu port discovery (rate=$NAABU_RATE type=$SCAN_TYPE)"
naabu_rc=0
naabu "${naabu_args[@]}" || naabu_rc=$?

# A failed discovery must never be reported as a clean scan.
if [ "$naabu_rc" -ne 0 ] && [ ! -s "$NAABU_JSON" ]; then
    die "naabu failed (exit $naabu_rc) and produced no results. Check NAABU_* settings — NAABU_TOP_PORTS accepts only 100, 1000, or full; use NAABU_PORTS for an arbitrary list."
fi
[ "$naabu_rc" -eq 0 ] || log "naabu exited $naabu_rc but wrote partial results; continuing"

if [ ! -s "$NAABU_JSON" ]; then
    log "no open ports discovered; nothing to hand to nmap or nuclei"
    printf 'scan %s: no open ports found\n' "$RUN_ID" > "$RUN_DIR/summary.txt"
    exit 0
fi

# host<TAB>comma,separated,ports
HOSTPORTS="$RUN_DIR/hostports.tsv"
jq -r '[(.ip // .host), (.port|tostring)] | @tsv' "$NAABU_JSON" \
    | sort -u \
    | awk -F'\t' '{ports[$1] = (ports[$1] == "" ? $2 : ports[$1] "," $2)}
                  END {for (h in ports) print h "\t" ports[h]}' \
    > "$HOSTPORTS"

log "discovered $(count "$NAABU_JSON") open ports across $(count "$HOSTPORTS") hosts"

# ---------------------------------------------------------------- nmap

if [ "$SKIP_NMAP" != "true" ]; then
    log "stage 2/3: nmap service detection on discovered ports only"
    while IFS=$'\t' read -r host ports; do
        [ -n "$host" ] || continue
        safe_host="$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_')"
        log "  nmap $host ($ports)"
        # NMAP_ARGS is intentionally word-split: it is an operator-supplied flag string.
        nmap $NMAP_ARGS -p "$ports" -oA "$RUN_DIR/nmap/$safe_host" "$host" \
            > /dev/null 2>&1 || log "  nmap failed for $host"
    done < "$HOSTPORTS"
else
    log "stage 2/3: nmap skipped (SKIP_NMAP=true)"
fi

# ---------------------------------------------------------------- nuclei

if [ "$SKIP_NUCLEI" != "true" ]; then
    NUCLEI_TARGETS="$RUN_DIR/nuclei-targets.txt"
    jq -r '[(.ip // .host), (.port|tostring)] | join(":")' "$NAABU_JSON" | sort -u > "$NUCLEI_TARGETS"

    if [ "$NUCLEI_UPDATE" = "true" ]; then
        log "refreshing nuclei templates"
        nuclei -update-templates -silent || log "template update failed, using baked-in set"
    fi

    nuclei_args=(
        -list "$NUCLEI_TARGETS"
        -jsonl
        -o "$RUN_DIR/nuclei.jsonl"
        -severity "$NUCLEI_SEVERITY"
        -rate-limit "$NUCLEI_RATE"
        -c "$NUCLEI_CONCURRENCY"
        -stats
        -disable-update-check
    )
    [ -n "$NUCLEI_TAGS" ] && nuclei_args+=( -tags "$NUCLEI_TAGS" )

    log "stage 3/3: nuclei against $(count "$NUCLEI_TARGETS") host:port pairs (severity=$NUCLEI_SEVERITY)"
    nuclei "${nuclei_args[@]}" || log "nuclei exited non-zero, continuing"
else
    log "stage 3/3: nuclei skipped (SKIP_NUCLEI=true)"
fi

# ---------------------------------------------------------------- summary

SUMMARY="$RUN_DIR/summary.txt"
{
    printf 'netscan-appliance run %s\n' "$RUN_ID"
    printf 'targets:      %s\n' "$(count "$RESOLVED_TARGETS")"
    printf 'hosts up:     %s\n' "$(count "$HOSTPORTS")"
    printf 'open ports:   %s\n' "$(count "$NAABU_JSON")"
    if [ -s "$RUN_DIR/nuclei.jsonl" ]; then
        printf 'findings:     %s\n\n' "$(count "$RUN_DIR/nuclei.jsonl")"
        printf 'findings by severity:\n'
        jq -r '.info.severity' "$RUN_DIR/nuclei.jsonl" | sort | uniq -c | sort -rn
        printf '\ntop findings:\n'
        jq -r '"  [" + .info.severity + "] " + .info.name + " -> " + (.["matched-at"] // .host // "")' \
            "$RUN_DIR/nuclei.jsonl" 2>/dev/null | head -40 || true
    else
        printf 'findings:     0\n'
    fi
    printf '\nopen ports by host:\n'
    sed 's/^/  /' "$HOSTPORTS"
} > "$SUMMARY"

cat "$SUMMARY"

# The container runs as root (naabu SYN scan needs raw sockets), so results would
# otherwise be root-owned on the host and unmanageable by the operator.
if [ -n "${PUID:-}" ]; then
    chown -R "${PUID}:${PGID:-$PUID}" "$RUN_DIR" || log "could not chown results to ${PUID}"
fi

log "done. artifacts in $RUN_DIR"
