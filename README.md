# netscan-appliance

Lightweight network scanning appliance: **naabu → nmap → nuclei**, in one container.

Built as a low-resource alternative to an nmap + OpenVAS stack. naabu does fast port
discovery, nmap does service detection *only on the ports naabu found*, and nuclei runs
template-based vulnerability checks against the discovered services.

## Web UI

A small branded web interface for running scans in front of a client: enter the
target networks, watch progress, and hand over a formatted findings report.

```bash
docker compose up -d web
```

Then open `https://<appliance-ip>:8080` (see TLS below — the first visit will warn about the self-signed certificate).

**The password is set at install time.** `install.sh` prompts for one; press Enter
to generate a strong one instead. See Passwords below.



| Variable | Default | Notes |
|---|---|---|
| `WEBUI_PASSWORD` | *(generated)* | Password for the sign-in page |
| `WEBUI_SECRET` | *(random)* | Session key; set it to keep sessions across restarts |
| `WEBUI_PORT` | `8080` | Host port to publish |
| `BRAND_NAME` | `Network Defenders` | Shown in the header and report footer |
| `BRAND_TAGLINE` | `Network Security Assessment` | Sub-heading under the brand name |
| `HTTPS` | `true` | TLS on by default; `false` serves cleartext |
| `TLS_SAN` | — | **Set this** to the appliance's LAN IP/hostname (see below) |
| `TLS_CERT` / `TLS_KEY` | — | Paths to your own cert and key, if you'd rather supply them |

### TLS

The UI serves HTTPS by default using a self-signed certificate generated on first
start into `certs/`. It is **persisted**, so its fingerprint stays stable across
restarts — that is what makes it trustable. A certificate regenerated every boot
would have to be re-accepted each time, which only trains you to click through
warnings.

Set the appliance's address so the certificate matches the URL you actually use,
otherwise the browser reports a name mismatch even after you trust it:

```
TLS_SAN=192.168.1.50
```

Changing `TLS_SAN` regenerates the certificate; nothing else does.

On first connection, compare the fingerprint in `docker compose logs web` against
what the browser shows, then trust it. After that a warning means something real —
either the appliance was redeployed, or somebody is intercepting the connection.

What this does and does not buy you: it stops **passive** interception of your
password and of the scan findings — which are the more sensitive payload, since a
report is a map of the client's weaknesses. It does not stop an **active**
attacker unless you actually verify that fingerprint.

This is Flask's built-in server. That is fine for one operator on an appliance,
but it is not a hardened front end — put a real reverse proxy in front if you ever
expose it beyond an engagement.

Drop a `logo.png` (or `.jpg`/`.svg`) into `branding/` and the header uses it in
place of the built-in mark. The `branding/` directory is gitignored, so each
deployment carries its own assets.

The report has a **Print / Save as PDF** button and a dedicated print stylesheet,
which is usually how you'll hand findings over.

Scan profiles offered in the UI:

| Profile | What it does |
|---|---|
| Quick look | Top 100 ports, no vulnerability checks — fast lay of the land |
| Standard | Top 1000 ports, full template checks |
| Gentle | Slow rate and `-T2` timing for fragile or production networks |
| Thorough | All 65535 ports (slow) |

The CLI below remains available and is unaffected by the web service.

## Quick start

```bash
docker compose build
TARGET=scanme.nmap.org docker compose run --rm netscan
```

Results land in `./output/scan-<UTC timestamp>/`.

## Providing targets

Three ways, checked in this order:

1. **Command line** — `docker compose run --rm netscan 10.0.0.5 10.0.0.6`
2. **Env var** — `TARGET="10.0.0.5,10.0.0.6" docker compose run --rm netscan`
3. **Mounted file** — put a list in `targets/targets.txt` (see `targets.example.txt`)
   and just run `docker compose run --rm netscan`

Hostnames, IPs, and CIDR ranges all work.

## Output

Each run creates `output/scan-<timestamp>/` containing:

| File | Contents |
|---|---|
| `summary.txt` | Human-readable rollup — read this first |
| `naabu.json` | Every open port found (JSONL) |
| `hostports.tsv` | host → comma-separated open ports |
| `nmap/<host>.{nmap,xml,gnmap}` | Service/version detection per host |
| `nuclei.jsonl` | Vulnerability findings (JSONL) |
| `targets.txt` | Exactly what was scanned, for the engagement record |

## Tuning

All knobs are environment variables. Defaults are deliberately conservative.

| Variable | Default | Notes |
|---|---|---|
| `SCAN_TYPE` | `s` | `s` = SYN (needs NET_RAW), `c` = TCP connect (unprivileged) |
| `NAABU_TOP_PORTS` | `1000` | Only `100`, `1000`, or `full` are valid. Ignored if `NAABU_PORTS` is set |
| `NAABU_PORTS` | — | Explicit list, e.g. `80,443,8080-8090`, or `-` for all 65535 |
| `NAABU_RATE` | `1000` | Packets/sec. Drop to ~200 on fragile networks |
| `NAABU_CONCURRENCY` | `25` | |
| `NMAP_ARGS` | `-sV -Pn -T3` | Add `-sC` for default scripts, `-T2` to go quieter |
| `NUCLEI_SEVERITY` | `low,medium,high,critical` | Add `info` for recon-grade noise |
| `NUCLEI_TAGS` | — | e.g. `cve,exposure` to narrow the template set |
| `NUCLEI_RATE` | `150` | Requests/sec |
| `NUCLEI_CONCURRENCY` | `25` | |
| `NUCLEI_UPDATE` | `false` | `true` refreshes templates before scanning |
| `SKIP_NMAP` | `false` | Port discovery + nuclei only |
| `SKIP_NUCLEI` | `false` | Port discovery + service detection only |

Nuclei templates are baked into the image at build time, so a freshly deployed
appliance can scan immediately without pulling ~10k templates over the client's
network. Rebuild the image (or set `NUCLEI_UPDATE=true`) to refresh them.

### Resource limits

`docker-compose.yml` caps the container at 2 CPUs / 2 GB. Adjust the `deploy.resources`
block per appliance. For a Pi-class box, try 1 CPU / 512 MB with `NAABU_RATE=200` and
`NUCLEI_CONCURRENCY=10`.

## Deploying to a new client appliance

Full start-to-finish runbook, including Debian install: **[DEPLOY.md](DEPLOY.md)**.

Summary:

Before travelling: confirm written authorisation and agreed scope, and place the
host where it can route to the networks being assessed.

**1. Provision the host** — a VM or physical box on the target segment, Debian or
Ubuntu, with Docker and git installed.

**2. Install.** One line on a fresh Debian or Ubuntu box — installs Docker and git
if missing, clones, prompts for a password, builds, and starts:

```bash
curl -fsSL https://raw.githubusercontent.com/mrecio87/nd-scanner/main/install.sh | bash
```

Or, on a machine that already has Docker:

```bash
git clone https://github.com/mrecio87/nd-scanner.git netscan-appliance && cd netscan-appliance && ./setup.sh --prompt
```

`setup.sh` detects the LAN address and writes `TLS_SAN`, generates a unique
password and session key, sets `PUID`/`PGID` so results are yours rather than
root's, builds the image, starts the UI, and prints the URL, password, and
certificate fingerprint. It is idempotent — re-running preserves everything
already configured, so it is safe to run again after a reboot.

If the site blocks outbound internet the build will fail; carry the image instead
(`docker save` / `docker load`, see above) and run `./setup.sh` afterwards, which
will reuse the loaded image.

**3. Verify the certificate.** On first connect compare the fingerprint the script
printed against the one the browser shows. That comparison is what makes a
self-signed certificate meaningful. Import it into your trust store only if the
client will be looking at the screen — importing removes the warning page but adds
no security.

**4. Scan.** Enter scope in the UI and run a **Quick look** first to confirm you
can actually reach the targets, then run the real scan.

**5. Decommission.** `output/` holds that client's complete vulnerability map.
Before the appliance leaves site or is reused elsewhere:

```bash
docker compose down && rm -rf output/scan-* certs/
```

`setup.sh` warns if it finds another client's results still present.

### Passwords

Each appliance has its own password, set when you install it.

The one-line installer prompts for one before anything starts listening — press
Enter and it generates a strong one instead:

```
Password for the web UI (Enter to generate one):
```

`./setup.sh --prompt` does the same on an existing checkout, and
`./setup.sh --password '...'` sets it non-interactively for provisioning
scripts (the value lands in your shell history, so prefer `--prompt` by hand).

With no flag at all, `setup.sh` keeps whatever is already in `.env`, or generates
a password on a fresh box and prints it once. The UI is never left without one.

Keep them in a password manager, one entry per appliance. To change a password
later, edit `WEBUI_PASSWORD` in `.env` and run `docker compose up -d web`, or
just re-run `./setup.sh --prompt`.

There is deliberately no shared fleet credential. One password across every
appliance means anyone who obtains it at one site can reach every other box you
have deployed, and revoking it means visiting all of them. If you later need to
know which technician ran which scan, that calls for per-technician accounts
rather than a shared secret.

## Scope note

`output/` and real target lists are gitignored — client scan data must not end up in
the repo. Only `targets/targets.example.txt` is tracked.

Only scan hosts you have written authorization to test.
