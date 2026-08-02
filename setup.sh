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

  (no options)        Use the fleet password from fleet.hash if present,
                      otherwise generate a unique password for this appliance.
      --new-fleet-password
                      Set (or rotate) the fleet password. Prompts for it, writes
                      its hash to fleet.hash, applies it to THIS appliance, and
                      tells you to commit and push so the rest of the fleet picks
                      it up. The plaintext is never written to the repo.
  -f, --fleet         Prompt for a shared password and store it in this box's
                      .env as plaintext. Prefer --new-fleet-password.
      --password PW   Set the password non-interactively. Convenient for
                      provisioning scripts, but the value lands in your shell
                      history -- prefer --fleet when typing by hand.
  -h, --help          Show this.

Everything else (LAN address, session key, PUID/PGID, certificate) is detected
or generated per appliance and preserved across re-runs.
USAGE
}

FLEET=0
CLI_PASSWORD=""
NEW_FLEET_HASH=0
NEW_HASH_WRITTEN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --new-fleet-password) NEW_FLEET_HASH=1; shift ;;
        -f|--fleet)     FLEET=1; shift ;;
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

# ------------------------------------------------- fleet password (one-off)

if [ "$NEW_FLEET_HASH" = "1" ]; then
    head_ "Setting the fleet password"
    say "This runs once. The hash goes in the repo; the password itself does not."
    say ""
    while :; do
        printf '  Fleet password: '; read -rs p1; printf '\n'
        printf '  Confirm:        '; read -rs p2; printf '\n'
        [ -n "$p1" ] || { warn "Empty. Try again."; continue; }
        [ "$p1" = "$p2" ] || { warn "They do not match. Try again."; continue; }
        if [ "${#p1}" -lt 12 ]; then
            warn "Under 12 characters. Its hash will sit in the repo, so make it
      strong enough to survive the repo leaking. Keep it in your password
      manager -- technicians paste it, they do not have to memorise it."
            printf '  Use it anyway? [y/N] '; read -r ok
            case "$ok" in [yY]*) ;; *) continue ;; esac
        fi
        break
    done

    d "docker compose build" >/dev/null 2>&1 || die "Build failed; cannot hash without the image."
    H="$(printf '%s\n' "$p1" | d "docker compose run --rm --no-deps -T --entrypoint python3 web /opt/webui/app.py --hash" | tr -d '\r')"
    case "$H" in
        scrypt:*) ;;
        *) die "Hashing failed. Got: ${H:-<empty>}" ;;
    esac

    {
        printf '# Fleet password hash (scrypt). Safe to commit: this is a one-way\n'
        printf '# hash, not the password. Any appliance cloning this repo will\n'
        printf '# authenticate with the fleet password automatically.\n'
        printf '# Regenerate with: ./setup.sh --new-fleet-password\n'
        printf '%s\n' "$H"
    } > fleet.hash

    say "wrote fleet.hash"
    # Deliberately does NOT exit: writing the hash and leaving this appliance on
    # the previous password is the obvious trap, and it is not obvious from the
    # outside that anything is wrong -- the login simply keeps rejecting you.
    # Fall through and apply it here as well.
    NEW_HASH_WRITTEN=1
fi

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

set_password() {
    # A plaintext password for this box overrides the fleet hash; drop the hash
    # so .env has exactly one source of truth.
    sed -i -e '/^WEBUI_PASSWORD=/d' -e '/^WEBUI_PASSWORD_HASH=/d' .env
    env_add WEBUI_PASSWORD "$1"
}
set_hash()     { sed -i '/^WEBUI_PASSWORD_HASH=/d' .env; env_add WEBUI_PASSWORD_HASH "$1"; }

NEW_PASSWORD=""
FLEET_SET=0
FLEET_HASHED=0
if [ -f fleet.hash ] && [ -s fleet.hash ] && [ -z "$CLI_PASSWORD" ] && [ "$FLEET" = "0" ] \
   && { [ "$NEW_HASH_WRITTEN" = "1" ] \
        || ! { env_has WEBUI_PASSWORD && [ -n "$(grep -E '^WEBUI_PASSWORD=' .env | cut -d= -f2-)" ]; }; }; then
    # The fleet password travels with the repo as a hash, so a new appliance
    # authenticates with the fleet credential without anyone typing it here.
    sed -i '/^WEBUI_PASSWORD=/d' .env
    set_hash "$(grep -v '^#' fleet.hash | grep -m1 . )"
    FLEET_HASHED=1
    say "password:  using the fleet password (verified against fleet.hash)"
elif [ -n "$CLI_PASSWORD" ]; then
    set_password "$CLI_PASSWORD"
    FLEET_SET=1
    say "password:  set from --password"
elif [ "$FLEET" = "1" ]; then
    while :; do
        printf '  Fleet password: '
        read -rs p1; printf '\n'
        printf '  Confirm:        '
        read -rs p2; printf '\n'
        [ -n "$p1" ] || { warn "Empty. Try again."; continue; }
        [ "$p1" = "$p2" ] || { warn "They do not match. Try again."; continue; }
        if [ "${#p1}" -lt 12 ]; then
            warn "Under 12 characters. This one credential opens every appliance
      in the fleet, including boxes sitting on networks you do not control."
            printf '  Use it anyway? [y/N] '
            read -r ok
            case "$ok" in [yY]*) ;; *) continue ;; esac
        fi
        set_password "$p1"
        FLEET_SET=1
        say "password:  fleet password set"
        break
    done
elif env_has WEBUI_PASSWORD && [ -n "$(grep -E '^WEBUI_PASSWORD=' .env | cut -d= -f2-)" ]; then
    say "password:  keeping the one already in .env"
else
    sed -i '/^WEBUI_PASSWORD=$/d' .env
    # cut, not head: under `set -o pipefail` a truncating head closes the pipe
    # and the SIGPIPE from tr would abort the whole script.
    NEW_PASSWORD="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-20)"
    env_add WEBUI_PASSWORD "$NEW_PASSWORD"
    say "password:  generated (shown at the end -- save it now, it is not repeated)"
fi

# Session key, so logins survive a container restart.
env_has WEBUI_SECRET || env_add WEBUI_SECRET \
    "$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | cut -c1-64)"

# Results should belong to the operator, not root.
env_has PUID || env_add PUID "$(id -u)"
env_has PGID || env_add PGID "$(id -g)"

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

# --------------------------------------------------------------- build/run

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
elif [ "$FLEET_HASHED" = "1" ]; then
    say "  Password:    the fleet password (from fleet.hash -- see your password manager)"
elif [ "$FLEET_SET" = "1" ]; then
    say "  Password:    (the fleet password you just set)"
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
say "  Only scan what you have written authorisation to test."
say ""

if [ "$NEW_HASH_WRITTEN" = "1" ]; then
    head_ "One more step"
    say "This appliance is already using the new fleet password. To roll it out"
    say "to the rest of the fleet, commit and push the hash:"
    say ""
    say "    git add fleet.hash && git commit -m 'Rotate fleet password' && git push"
    say ""
    say "Other appliances pick it up on their next 'git pull' + ./setup.sh."
    say "Keep the password in your password manager -- it cannot be recovered"
    say "from the hash."
    say ""
fi
