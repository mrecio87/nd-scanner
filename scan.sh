#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="${OUTPUT_ROOT:-/output}"
TARGETS_FILE="${TARGETS_FILE:-/targets/targets.txt}"

SCAN_TYPE="${SCAN_TYPE:-s}"
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-1000}"
NAABU_PORTS="${NAABU_PORTS:-}"
NAABU_RATE="${NAABU_RATE:-1000}"
NAABU_CONCURRENCY="${NAABU_CONCURRENCY:-25}"

# Used only when SCAN_TYPE=auto. HOST_SUBNETS is written by setup.sh from the
# host's directly-attached routes, because the container behind a bridge cannot
# see them itself.
HOST_SUBNETS="${HOST_SUBNETS:-}"
NAABU_RATE_LOCAL="${NAABU_RATE_LOCAL:-2000}"
NAABU_RATE_ROUTED="${NAABU_RATE_ROUTED:-300}"

# Written by setup.sh from this host's own interface addresses. A target range
# that happens to include the appliance finds its own management port and
# would otherwise aim nuclei's full template set at the process serving the
# page the operator is watching. Empty this in .env to include the appliance
# in its own scans on purpose.
APPLIANCE_IPS="${APPLIANCE_IPS:-127.0.0.1}"

NMAP_ARGS="${NMAP_ARGS:--sV -O -Pn -T3}"

NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-info,low,medium,high,critical}"
NUCLEI_RATE="${NUCLEI_RATE:-150}"
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-25}"
NUCLEI_TAGS="${NUCLEI_TAGS:-}"
NUCLEI_UPDATE="${NUCLEI_UPDATE:-false}"

SKIP_NMAP="${SKIP_NMAP:-false}"
SKIP_NUCLEI="${SKIP_NUCLEI:-false}"

# Raw printing (9100-9107 JetDirect/AppSocket, 515 LPD): no request/response
# framing, so whatever bytes a client sends get put on paper. nmap's own
# nmap-service-probes ships an "Exclude T:9100-9107" line for exactly this
# reason -- and that Exclude directive keeps nmap from sending ANY probe to
# the port, not just -sV ones. A live scan proved the same caution applies to
# plain port discovery too: even naabu's payload-free SYN/connect probe was
# enough to make a real printer print gibberish until it ran out of paper
# (confirmed against a synthetic listener that received zero bytes -- real
# JetDirect firmware is far less well-behaved than a test socket). So naabu
# itself is now told to skip these ports outright via -exclude-ports; nothing
# this scanner sends ever reaches them. Always excluded; not a scan-time
# choice. Because naabu no longer touches the port, this scan also cannot
# confirm whether it is actually open on any given host -- see
# noprobe-policy.json / the report's scope note instead of a per-host finding.
NOPROBE_PORTS="${NOPROBE_PORTS:-9100,9101,9102,9103,9104,9105,9106,9107,515}"

# Fragile industrial/building-automation protocols (502 Modbus, 102 Siemens
# S7comm, 47808 BACnet/IP, 44818 EtherNet/IP CIP, 20000 DNP3): documented to
# crash or hang on ordinary scan traffic -- small connection tables and
# minimal input validation mean even a routine version-detection probe, let
# alone a vulnerability template, can take a PLC offline. Unlike raw printing
# this is an operator choice (the "Avoid Scanning Fragile Devices" checkbox
# in the web UI): excluding them loses a legitimate finding if the client
# really does have an exposed, unauthenticated control-system port, so
# AVOID_FRAGILE_ICS defaults to on but can be turned off per scan. When on,
# these ports are excluded from naabu itself for the same reason as raw
# printing above -- the checkbox means "avoid scanning", not "avoid deep
# scanning".
FRAGILE_ICS_PORTS="${FRAGILE_ICS_PORTS:-502,102,47808,44818,20000}"
AVOID_FRAGILE_ICS="${AVOID_FRAGILE_ICS:-true}"

EFFECTIVE_NOPROBE_PORTS="$NOPROBE_PORTS"
if [ "$AVOID_FRAGILE_ICS" = "true" ]; then
    EFFECTIVE_NOPROBE_PORTS="$EFFECTIVE_NOPROBE_PORTS,$FRAGILE_ICS_PORTS"
fi

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

# ------------------------------------------------- scan type and rate (auto)
#
# SYN scanning is fast but leaves half-open connections that a stateful
# firewall records and eventually blocks. That only matters when something sits
# between us and the target, so pick per run.

if [ "$SCAN_TYPE" = "auto" ]; then
    LOCALITY="$(python3 /usr/local/bin/locality.py "$HOST_SUBNETS" "$RESOLVED_TARGETS" 2>/dev/null || echo routed)"
    if [ "$LOCALITY" = "local" ]; then
        SCAN_TYPE="s"
        NAABU_RATE="$NAABU_RATE_LOCAL"
        log "auto: every target is on a directly attached subnet, using SYN at ${NAABU_RATE}/s"
    else
        SCAN_TYPE="c"
        NAABU_RATE="$NAABU_RATE_ROUTED"
        log "auto: at least one target is routed, using connect scan at ${NAABU_RATE}/s"
    fi
fi

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
    -exclude-ports "$EFFECTIVE_NOPROBE_PORTS"
)
if [ -n "$NAABU_PORTS" ]; then
    naabu_args+=( -p "$NAABU_PORTS" )
else
    naabu_args+=( -top-ports "$NAABU_TOP_PORTS" )
fi

log "stage 1/3: naabu port discovery (rate=$NAABU_RATE type=$SCAN_TYPE); raw/print ports never touched (avoid_fragile_ics=$AVOID_FRAGILE_ICS)"
naabu_rc=0
naabu "${naabu_args[@]}" || naabu_rc=$?

# A failed discovery must never be reported as a clean scan.
if [ "$naabu_rc" -ne 0 ] && [ ! -s "$NAABU_JSON" ]; then
    die "naabu failed (exit $naabu_rc) and produced no results. Check NAABU_* settings. NAABU_TOP_PORTS accepts only 100, 1000, or full; use NAABU_PORTS for an arbitrary list."
fi
[ "$naabu_rc" -eq 0 ] || log "naabu exited $naabu_rc but wrote partial results; continuing"

if [ ! -s "$NAABU_JSON" ]; then
    log "no open ports discovered; nothing to hand to nmap or nuclei"
    printf 'scan %s: no open ports found\n' "$RUN_ID" > "$RUN_DIR/summary.txt"
    exit 0
fi

# Drop the appliance's own addresses before anything downstream is built from
# this file, so both nmap and nuclei -- which derive their target lists from
# it -- never see them. naabu itself already ran; a SYN probe is harmless,
# nuclei's exploitation-style templates against our own web UI are not.
if [ -n "$APPLIANCE_IPS" ]; then
    SELF_JSON="$(printf '%s' "$APPLIANCE_IPS" | tr ',' '\n' | sed '/^$/d' | jq -R . | jq -cs .)"
    _before="$(count "$NAABU_JSON")"
    jq -c --argjson self "$SELF_JSON" \
        'select((((.ip // .host) as $h | $self | index($h)) // false) | not)' \
        "$NAABU_JSON" > "$NAABU_JSON.tmp" && mv "$NAABU_JSON.tmp" "$NAABU_JSON"
    _after="$(count "$NAABU_JSON")"
    if [ "$_before" != "$_after" ]; then
        log "excluded $((_before - _after)) result(s) on this appliance's own address ($APPLIANCE_IPS)"
    fi
fi

if [ ! -s "$NAABU_JSON" ]; then
    log "nothing left to scan after excluding this appliance's own address"
    printf 'scan %s: no open ports found (this appliance was the only host discovered)\n' "$RUN_ID" \
        > "$RUN_DIR/summary.txt"
    exit 0
fi

# naabu was told (via -exclude-ports, above) to never touch raw/print or
# (if avoid_fragile_ics) fragile-ICS ports at all, so every port in
# NAABU_JSON at this point is already safe to actively probe -- there is
# nothing left to filter out here.
HOSTPORTS="$RUN_DIR/hostports.tsv"
jq -r '[(.ip // .host), (.port|tostring)] | @tsv' "$NAABU_JSON" \
    | sort -u \
    | awk -F'\t' '{ports[$1] = (ports[$1] == "" ? $2 : ports[$1] "," $2)}
                  END {for (h in ports) print h "\t" ports[h]}' \
    > "$HOSTPORTS"

# Record what was excluded so the report can note it as a scope limitation.
# Nothing in naabu.json can answer "was it actually open" any more -- naabu
# never touched the port, so this is a policy record, not an observation.
NOPROBE_POLICY="$RUN_DIR/noprobe-policy.json"
jq -n --arg print_ports "$NOPROBE_PORTS" --arg ics_ports "$FRAGILE_ICS_PORTS" \
      --argjson avoid_ics "$([ "$AVOID_FRAGILE_ICS" = "true" ] && printf true || printf false)" \
    '{raw_print_ports: $print_ports, fragile_ics_ports: $ics_ports, avoid_fragile_ics: $avoid_ics}' \
    > "$NOPROBE_POLICY"

log "discovered $(count "$NAABU_JSON") open ports across $(count "$HOSTPORTS") hosts (raw/print ports never touched; fragile ICS ports also skipped when avoid_fragile_ics=true)"

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
    printf 'nd-scanner run %s\n' "$RUN_ID"
    printf 'targets:      %s\n' "$(count "$RESOLVED_TARGETS")"
    printf 'hosts up:     %s\n' "$(jq -r '(.ip // .host)' "$NAABU_JSON" | sort -u | wc -l)"
    printf 'open ports:   %s\n' "$(count "$NAABU_JSON")"
    printf 'ports never scanned (not probed at all, not even for discovery): raw/print=%s; fragile ICS/building-automation=%s (avoided=%s)\n' \
        "$NOPROBE_PORTS" "$FRAGILE_ICS_PORTS" "$AVOID_FRAGILE_ICS"
    printf 'note: a host whose only open port is one of the above will not appear in this scan at all.\n'
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
