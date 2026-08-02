#!/usr/bin/env bash
#
# First-run setup for a new appliance. Idempotent: re-running keeps the
# password, certificate, and any settings you have already chosen.
#
set -euo pipefail
cd "$(dirname "$0")"

usage() {
    cat <<'USAGE'
Usage: ./setup.sh [options]

  (no options)        Keep the password already in .env, or generate one.
  -p, --prompt        Prompt for the password to use on this appliance.
      --password PW   Set it non-interactively, for provisioning scripts. The
                      value lands in your shell history -- prefer --prompt when
                      typing by hand.
  -h, --help          Show this.

Everything else (LAN address, session key, PUID/PGID, certificate) is detected
or generated per appliance and preserved across re-runs.
USAGE
}

PROMPT=0
CLI_PASSWORD=""
while [ $# -gt 0 ]; do
    case "$1" in
        -p|--prompt)    PROMPT=1; shift ;;
        --password)     CLI_PASSWORD="${2:-}"; shift 2 ;;
        --password=*)   CLI_PASSWORD="${1#*=}"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 1 ;;
    esac
done

BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

say()  { printf '  %s\n' "$*"; }
head_() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
warn() { printf '\n  [!] %s\n' "$*"; }
die()  { printf '\n  [!] %s\n\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------- preflight

head_ "Checking prerequisites"

command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it, then re-run this script."

USE_SG=0
if docker info >/dev/null 2>&1; then
    say "docker: ready"
elif command -v sg >/dev/null 2>&1 && sg docker -c 'docker info' >/dev/null 2>&1; then
    USE_SG=1
    say "docker: reachable via the 'docker' group"
    warn "Your shell predates your docker group membership. This run works around
      it, but log out and back in so plain 'docker' commands work."
else
    die "Cannot talk to the Docker daemon. Either add yourself to the docker group
      (sudo usermod -aG docker \$USER, then log out and back in) or run with sudo."
fi

d() {  # run a docker command, transparently handling the stale-group case
    if [ "$USE_SG" = "1" ]; then sg docker -c "$*"; else eval "$*"; fi
}

# ------------------------------------------------------ prior client data

if compgen -G "output/scan-*" >/dev/null 2>&1; then
    n=$(find output -maxdepth 1 -name 'scan-*' -type d | wc -l)
    warn "This host already holds $n scan result set(s) in ./output/."
    say "Those are a previous client's findings. If this appliance is being"
    say "redeployed to a different client, clear them before you continue:"
    say ""
    say "    rm -rf output/scan-*"
    say ""
    printf '  Continue without clearing? [y/N] '
    read -r reply
    case "$reply" in
        [yY]*) say "Continuing." ;;
        *)     die "Stopped. Clear ./output/ and re-run." ;;
    esac
fi

# ---------------------------------------------------------------- .env

head_ "Configuring this deployment"

touch .env
# Holds the appliance password: keep it off other local accounts.
chmod 600 .env
env_has() { grep -qE "^$1=" .env; }
env_add() { printf '%s=%s\n' "$1" "$2" >> .env; }

set_password() { sed -i '/^WEBUI_PASSWORD=/d' .env; env_add WEBUI_PASSWORD "$1"; }

gen_password() {
    # cut, not head: under `set -o pipefail` a truncating head closes the pipe
    # and the SIGPIPE from tr would abort the whole script.
    head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-20
}

NEW_PASSWORD=""
CHOSEN=0
if [ -n "$CLI_PASSWORD" ]; then
    set_password "$CLI_PASSWORD"
    CHOSEN=1
    say "password:  set from --password"
elif [ "$PROMPT" = "1" ]; then
    while :; do
        printf '  Password for the web UI (Enter to generate one): '
        read -rs p1; printf '\n'
        if [ -z "$p1" ]; then
            NEW_PASSWORD="$(gen_password)"
            set_password "$NEW_PASSWORD"
            say "password:  generated (shown at the end)"
            break
        fi
        printf '  Confirm:                                        '
        read -rs p2; printf '\n'
        [ "$p1" = "$p2" ] || { warn "They do not match. Try again."; continue; }
        if [ "${#p1}" -lt 12 ]; then
            warn "Under 12 characters. This appliance sits on a network you do
      not control while it scans."
            printf '  Use it anyway? [y/N] '
            read -r ok
            case "$ok" in [yY]*) ;; *) continue ;; esac
        fi
        set_password "$p1"
        CHOSEN=1
        say "password:  set"
        break
    done
elif env_has WEBUI_PASSWORD && [ -n "$(grep -E '^WEBUI_PASSWORD=' .env | cut -d= -f2-)" ]; then
    say "password:  keeping the one already in .env"
else
    NEW_PASSWORD="$(gen_password)"
    set_password "$NEW_PASSWORD"
    say "password:  generated (shown at the end -- save it now, it is not repeated)"
fi

# Session key, so logins survive a container restart.
env_has WEBUI_SECRET || env_add WEBUI_SECRET \
    "$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | cut -c1-64)"

# Results should belong to the operator, not root.
env_has PUID || env_add PUID "$(id -u)"
env_has PGID || env_add PGID "$(id -g)"

# The container sees only its bridge network, so it cannot tell which subnets
# are directly attached. Detect them here for SCAN_TYPE=auto. Refreshed every
# run, since an appliance moved to a new site lands on a different subnet.
SUBNETS="$(ip -4 -o route show scope link 2>/dev/null \
    | grep -vE ' dev (docker|br-|veth)' \
    | awk '{print $1}' | grep -E '^[0-9]+\.' | paste -sd, - || true)"
sed -i '/^HOST_SUBNETS=/d' .env
if [ -n "$SUBNETS" ]; then
    env_add HOST_SUBNETS "$SUBNETS"
    say "subnets:   $SUBNETS treated as directly attached"
fi

# The container cannot see the host's LAN address, so the certificate can only
# match the URL you actually browse to if we detect and pass it in.
if env_has TLS_SAN && [ -n "$(grep -E '^TLS_SAN=' .env | cut -d= -f2-)" ]; then
    LAN_IP="$(grep -E '^TLS_SAN=' .env | cut -d= -f2- | cut -d, -f1)"
    say "address:   keeping TLS_SAN=$LAN_IP from .env"
else
    LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)"
    if [ -z "$LAN_IP" ]; then
        warn "Could not detect a LAN address. Set TLS_SAN=<ip> in .env by hand,
      otherwise the certificate will never match the URL you use."
        LAN_IP="<appliance-ip>"
    else
        sed -i '/^TLS_SAN=$/d' .env
        env_add TLS_SAN "$LAN_IP"
        say "address:   detected $LAN_IP"
    fi
fi

# Every address this host answers on, so scan.sh can drop the appliance from
# its own target list. Docker publishes the web UI on 0.0.0.0, so it is
# reachable via every interface IP, not just the one used for TLS_SAN -- a
# scan of a whole subnet that happens to include this box otherwise finds its
# own management port and aims nuclei's full template set at the process
# serving the page the operator is watching.
SELF_IPS="$(ip -4 -o addr show scope global 2>/dev/null \
    | grep -vE ' (docker|br-|veth)' \
    | awk '{print $4}' | cut -d/ -f1 | paste -sd, - || true)"
sed -i '/^APPLIANCE_IPS=/d' .env
env_add APPLIANCE_IPS "127.0.0.1${SELF_IPS:+,$SELF_IPS}"
[ -n "$SELF_IPS" ] && say "address:   $SELF_IPS excluded from any scan this appliance runs"

# --------------------------------------------------------------- build/run

# Point the update check at whichever repository this checkout came from.
# Hardcoding one means a clone of the other always reports an update.
ORIGIN="$(git config --get remote.origin.url 2>/dev/null || echo '')"
SLUG="$(printf '%s' "$ORIGIN" | sed -E -e 's#\.git$##' -e 's#.*[:/]([^/]+/[^/]+)$#\1#')"
sed -i '/^UPDATE_CHECK_URL=/d' .env
if printf '%s' "$SLUG" | grep -qE '^[^/]+/[^/]+$'; then
    env_add UPDATE_CHECK_URL "https://api.github.com/repos/${SLUG}/commits/main"
fi

# Stamp the build so the UI can compare against the repository.
sed -i -e '/^BUILD_REF=/d' -e '/^BUILD_DATE=/d' .env
env_add BUILD_REF  "$(git rev-parse --short HEAD 2>/dev/null || echo '')"
env_add BUILD_DATE "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

head_ "Building the image"
say "First build pulls the tools and ~13k nuclei templates; expect a few minutes."
if ! d "docker compose build" > /tmp/netscan-build.log 2>&1; then
    printf '\n'
    tail -25 /tmp/netscan-build.log | sed 's/^/      /'
    die "Build failed. Full log: /tmp/netscan-build.log"
fi
say "done"

head_ "Starting the web UI"
if ! d "docker compose up -d web" > /tmp/netscan-start.log 2>&1; then
    printf '\n'
    tail -15 /tmp/netscan-start.log | sed 's/^/      /'
    die "Could not start the web service. Full log: /tmp/netscan-start.log"
fi

for _ in $(seq 1 30); do
    sleep 1
    d "docker compose logs web" 2>/dev/null | grep -q "Running on" && break
done

FP="$(d 'docker compose exec -T web openssl x509 -in /certs/appliance.crt -noout -fingerprint -sha256' 2>/dev/null | cut -d= -f2 || true)"
PORT="$(grep -E '^WEBUI_PORT=' .env | cut -d= -f2- || true)"
PORT="${PORT:-8080}"

# ----------------------------------------------------------------- summary

head_ "Ready"
say ""
say "  URL:         ${BOLD}https://${LAN_IP}:${PORT}${RESET}"
if [ -n "$NEW_PASSWORD" ]; then
    say "  Password:    ${BOLD}${NEW_PASSWORD}${RESET}"
    say "               ^ save this to your password manager now"
elif [ "$CHOSEN" = "1" ]; then
    say "  Password:    (the one you just set)"
else
    say "  Password:    (unchanged -- see WEBUI_PASSWORD in .env)"
fi
say ""
say "  Certificate fingerprint (SHA-256):"
say "    ${FP:-unavailable}"
say ""
say "  On first connect, check that fingerprint matches what the browser shows,"
say "  then proceed. That check is what makes the self-signed certificate"
say "  meaningful -- importing it only removes the warning screen."
say ""
say "  Scans run from this host, so it can only reach networks this host routes to."
say "  Only scan what you have written authorization to test."
say ""

