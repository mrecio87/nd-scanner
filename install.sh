#!/usr/bin/env bash
#
# One-line installer:
#
#   curl -fsSL https://raw.githubusercontent.com/mrecio87/nd-scanner/main/install.sh | bash
#
# Installs git and Docker if missing, clones the repository, and runs setup.sh.
#
# Environment overrides:
#   NETSCAN_DIR         where to install          (default: $HOME/nd-scanner)
#   NETSCAN_REPO        repository URL
#   NETSCAN_BRANCH      branch to check out       (default: main)
#   NETSCAN_PASSWORD    set the web UI password non-interactively; otherwise
#                       you are prompted (Enter generates a strong one)
#
set -euo pipefail

# Everything lives in a function invoked on the last line. If the download is
# truncated mid-flight, bash reaches EOF without ever calling main, rather than
# executing half a script.
main() {
    NETSCAN_DIR="${NETSCAN_DIR:-$HOME/nd-scanner}"
    NETSCAN_REPO="${NETSCAN_REPO:-https://github.com/mrecio87/nd-scanner.git}"
    NETSCAN_BRANCH="${NETSCAN_BRANCH:-main}"

    BOLD=$(tput bold 2>/dev/null || true)
    RESET=$(tput sgr0 2>/dev/null || true)
    say()   { printf '  %s\n' "$*"; }
    head_() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
    die()   { printf '\n  [!] %s\n\n' "$*" >&2; exit 1; }

    # Piped from curl, stdin is the script itself -- reattach the terminal so
    # setup.sh can still prompt.
    if [ ! -t 0 ] && [ -r /dev/tty ]; then
        exec < /dev/tty
    fi

    head_ "netscan appliance installer"

    [ -r /etc/os-release ] || die "Unsupported system: no /etc/os-release."
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*) ;;
        *) die "This installer supports Debian and Ubuntu. Found: ${PRETTY_NAME:-unknown}" ;;
    esac
    say "system:  ${PRETTY_NAME:-unknown}"

    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 \
            || die "Not root and sudo is not installed. Re-run as root."
        SUDO="sudo"
        say "sudo:    will prompt for your password"
    fi

    # ------------------------------------------------------------ packages

    need_docker=0
    command -v docker >/dev/null 2>&1 || need_docker=1
    need_git=0
    command -v git >/dev/null 2>&1 || need_git=1

    if [ "$need_git" = "1" ] || [ "$need_docker" = "1" ]; then
        head_ "Installing prerequisites"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq git ca-certificates curl >/dev/null
        say "git: installed"
    else
        say "git:     already installed"
        say "docker:  already installed"
    fi

    if [ "$need_docker" = "1" ]; then
        say "docker:  installing from Docker's own repository"
        $SUDO install -m 0755 -d /etc/apt/keyrings
        $SUDO curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
            -o /etc/apt/keyrings/docker.asc
        $SUDO chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
            | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin >/dev/null
        say "docker:  installed"
    fi

    if [ "$(id -u)" -ne 0 ] && ! id -nG | tr ' ' '\n' | grep -qx docker; then
        $SUDO usermod -aG docker "$USER"
        say "docker:  added $USER to the docker group"
    fi

    # -------------------------------------------------------------- clone

    head_ "Fetching the appliance"
    if [ -d "$NETSCAN_DIR/.git" ]; then
        say "updating existing checkout at $NETSCAN_DIR"
        git -C "$NETSCAN_DIR" fetch --quiet origin "$NETSCAN_BRANCH"
        git -C "$NETSCAN_DIR" checkout --quiet "$NETSCAN_BRANCH"
        git -C "$NETSCAN_DIR" merge --quiet --ff-only "origin/$NETSCAN_BRANCH" \
            || die "Local changes conflict with the update. Resolve them in $NETSCAN_DIR."
    else
        [ -e "$NETSCAN_DIR" ] && die "$NETSCAN_DIR exists but is not a git checkout."
        git clone --quiet --branch "$NETSCAN_BRANCH" "$NETSCAN_REPO" "$NETSCAN_DIR"
        say "cloned into $NETSCAN_DIR"
    fi

    cd "$NETSCAN_DIR"

    # -------------------------------------------------------------- setup

    [ -x ./setup.sh ] || chmod +x ./setup.sh

    # --prompt asks for the password before anything starts listening, so the
    # UI is never reachable unauthenticated. NETSCAN_PASSWORD skips the prompt
    # for unattended provisioning.
    if [ -n "${NETSCAN_PASSWORD:-}" ]; then
        exec ./setup.sh --password "$NETSCAN_PASSWORD"
    fi
    exec ./setup.sh --prompt
}

main "$@"
