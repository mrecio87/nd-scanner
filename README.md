# netscan-appliance

A self-contained network scanning appliance that runs as a single Docker
container. Give it a range and it finds live hosts and open ports, identifies the
services behind them, tests those services against a vulnerability template set,
and produces a readable report.

Built to run on modest hardware — a scan is network-bound rather than
compute-bound.

# Install

You need a Debian or Ubuntu machine, physical or virtual, on a network that can
route to whatever you intend to scan. Nothing else needs installing first.

```bash
curl -fsSL https://raw.githubusercontent.com/mrecio87/nd-scanner/main/install.sh | bash
```

It installs Docker and git if missing, clones to `~/netscan-appliance`, asks for a
password, builds, and starts the web interface. At the prompt, type a password or
press Enter to generate one — either way it is printed at the end, so save it
before closing the terminal.

The first build pulls the scanning tools and vulnerability templates, so give it a
few minutes. It finishes by printing the URL, the password, and the certificate
fingerprint.

Open the URL. The browser warns about the self-signed certificate — compare the
fingerprint against the one just printed, then continue and sign in. That
comparison is what makes a self-signed certificate worth anything.

If the installer adds you to the `docker` group, log out and back in before
running Docker commands by hand.

Re-running `./setup.sh` is safe: it keeps the password, certificate, and settings
already in place, so use it after a reboot or an address change.

**Already have Docker:**

```bash
git clone https://github.com/mrecio87/nd-scanner.git netscan-appliance && cd netscan-appliance && ./setup.sh --prompt
```

**No internet where it will run:** build somewhere with connectivity, carry the
image over, then run `./setup.sh`.

```bash
docker save netscan-appliance:latest | gzip > netscan.tar.gz
gunzip -c netscan.tar.gz | docker load
```

# Running a scan

Sign in, enter target networks one per line, pick a profile, start. The page shows
live progress, and the finished report has a Print / Save as PDF button.

| Profile | What it does |
|---|---|
| Quick look | Top 100 ports, no vulnerability checks — fast lay of the land |
| Standard | Top 1000 ports, full template checks |
| Gentle | Slow rate and `-T2` timing for fragile or production networks |
| Thorough | All 65535 ports (slow) |

On an unfamiliar network run Quick look first — a couple of minutes tells you
whether you can reach the targets at all before committing to a long scan.

# Command line

Works alongside the web interface and is unaffected by it.

```bash
docker compose run --rm netscan 10.0.0.5
TARGET="10.0.0.5,10.0.0.6" docker compose run --rm netscan
```

Or list targets in `targets/targets.txt`, one per line, and run with no arguments.
Hostnames, IPs, and CIDR ranges all work.

# Output

Each run creates `output/scan-<UTC timestamp>/`:

| File | Contents |
|---|---|
| `summary.txt` | Human-readable rollup — read this first |
| `naabu.json` | Every open port found (JSONL) |
| `hostports.tsv` | host → comma-separated open ports |
| `nmap/<host>.{nmap,xml,gnmap}` | Service and version detection per host |
| `nuclei.jsonl` | Vulnerability findings (JSONL) |
| `targets.txt` | Exactly what was scanned, for the engagement record |

# Configuration

Environment variables in `.env`. Defaults are deliberately conservative.

| Variable | Default | Notes |
|---|---|---|
| `WEBUI_PASSWORD` | *(generated)* | Password for the sign-in page |
| `WEBUI_SECRET` | *(random)* | Session key; set it to keep sessions across restarts |
| `WEBUI_PORT` | `8080` | Host port to publish |
| `BRAND_NAME` | `Network Defenders` | Shown in the header and report footer |
| `BRAND_TAGLINE` | `Network Security Assessment` | Sub-heading under the brand name |
| `HTTPS` | `true` | TLS on by default; `false` serves cleartext |
| `TLS_SAN` | *(auto-detected)* | Extra addresses for the certificate |
| `TLS_CERT` / `TLS_KEY` | — | Paths to your own certificate and key |
| `SCAN_TYPE` | `s` | `s` = SYN (needs NET_RAW), `c` = TCP connect (unprivileged) |
| `NAABU_TOP_PORTS` | `1000` | Only `100`, `1000`, or `full`. Ignored if `NAABU_PORTS` is set |
| `NAABU_PORTS` | — | Explicit list, e.g. `80,443,8080-8090`, or `-` for all 65535 |
| `NAABU_RATE` | `1000` | Packets/sec. Drop to ~200 on fragile networks |
| `NMAP_ARGS` | `-sV -Pn -T3` | Add `-sC` for default scripts, `-T2` to go quieter |
| `NUCLEI_SEVERITY` | `low,medium,high,critical` | Add `info` for inventory-level detail |
| `NUCLEI_TAGS` | — | e.g. `cve,exposure` to narrow the template set |
| `NUCLEI_RATE` | `150` | Requests/sec |
| `NUCLEI_UPDATE` | `false` | `true` refreshes templates before scanning |
| `SKIP_NMAP` / `SKIP_NUCLEI` | `false` | Drop a stage |

Templates are baked into the image, so a fresh appliance scans immediately without
pulling them over the client's network. `docker-compose.yml` caps the container at
2 CPUs and 2 GB; for a Pi-class box try 1 CPU and 512 MB with `NAABU_RATE=200`.

# Passwords

Each appliance has its own, set at install time. `./setup.sh --prompt` changes it
later; `./setup.sh --password '...'` sets it non-interactively for provisioning
scripts, at the cost of putting it in your shell history.

Keep them in a password manager, one per appliance. There is deliberately no
shared credential — one password everywhere means whoever obtains it at one site
can reach every other box you have deployed.

# Deploying to a client site

Full runbook, including the Debian install: **[DEPLOY.md](DEPLOY.md)**.

Confirm written authorisation and scope before travelling, verify the certificate
fingerprint on first connect, and clear results before the appliance leaves or is
reused — `output/` holds that client's complete vulnerability map.

```bash
docker compose down && rm -rf output/scan-* certs/
```

`output/` and real target lists are gitignored, so client data cannot reach the
repo. Only scan hosts you have written authorization to test.
