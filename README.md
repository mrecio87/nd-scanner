# nd-scanner

A self-contained network scanning appliance that runs as a single Docker
container. Give it a range and it finds live hosts and open ports, identifies the
services behind them, tests those services against a vulnerability template set,
and produces a readable report.

It runs fine on modest hardware. Scans spend most of their time waiting on the
network rather than working the CPU.

# Install

You need a Debian or Ubuntu machine, physical or virtual, on a network that can
route to whatever you intend to scan. Nothing else needs installing first.

```bash
curl -fsSL https://raw.githubusercontent.com/mrecio87/nd-scanner/main/install.sh | bash
```

It installs Docker and git if they are missing, clones to `~/nd-scanner`, asks for
a password, builds, and starts the web interface. At the prompt, type a password
or press Enter to generate one. Either way it is printed at the end, so save it
before closing the terminal.

The first build pulls the scanning tools and vulnerability templates, so give it a
few minutes. It finishes by printing the URL, the password, and the certificate
fingerprint.

Open the URL. The browser will warn about the self-signed certificate. Compare the
fingerprint it shows against the one just printed, then continue and sign in.
Without that check the certificate proves nothing.

If the installer adds you to the `docker` group, log out and back in before
running Docker commands by hand.

Re-running `./setup.sh` is safe. It keeps the password, certificate, and settings
already in place, so use it after a reboot or an address change.

**Already have Docker:**

```bash
git clone https://github.com/mrecio87/nd-scanner.git nd-scanner && cd nd-scanner && ./setup.sh --prompt
```

**No internet where it will run:** build somewhere with connectivity, carry the
image over, then run `./setup.sh`.

```bash
docker save nd-scanner:latest | gzip > nd-scanner.tar.gz
gunzip -c nd-scanner.tar.gz | docker load
```

# Running a scan

Sign in, enter target networks one per line, pick a profile, start. The page shows
live progress, and the finished report has a Print / Save as PDF button.

| Profile | What it does |
|---|---|
| Quick look | Top 100 ports, no vulnerability checks. Fast lay of the land |
| Standard | Top 1000 ports, full template checks |
| Gentle | Slow rate and `-T2` timing for fragile or production networks |
| Thorough | All 65535 ports (slow) |

On an unfamiliar network, run Quick look first. A couple of minutes tells you
whether you can reach the targets at all, before you commit to a long scan.

Each report page offers **Print / Save as PDF** plus exports: a standalone HTML
copy, CSV spreadsheets (inventory + findings), structured JSON, and a Nessus v2
XML file for importing into Tenable and similar tooling. The scans list has a
bulk export with the same format choices.

To see what changed since a previous scan, open a report and pick a run from the
"Compare this run with" box, or tick two scans on the list and press
**Compare two**. The comparison shows new and gone systems, ports that opened or
closed per host, and findings that are new, resolved, or moved to different hosts.

**Scheduled scans** re-run a network automatically. On the new-scan form, tick
"Repeat this scan on a schedule" and the frequency settings appear next to it:
daily, weekly, or every-N-hours, plus a profile and client name. Times are
24-hour UTC.

If a scheduled run comes due while another scan is still running (say a slow
scan overruns its own interval), each schedule chooses between **scan as soon
as possible** — it starts within seconds of the current scan finishing — or
**skip this occurrence** and wait for the next scheduled run. The appliance
never stacks two scans. Schedules live in `output/schedules.json`, so they
survive restarts and are wiped with the rest of a client's data when the
appliance is redeployed.

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
| `summary.txt` | Human-readable rollup. Read this first |
| `naabu.json` | Every open port found (JSONL) |
| `hostports.tsv` | host to comma-separated open ports |
| `nmap/<host>.{nmap,xml,gnmap}` | Service and version detection per host |
| `nuclei.jsonl` | Vulnerability findings (JSONL) |
| `targets.txt` | Exactly what was scanned, for the engagement record |

# Configuration

Environment variables in `.env`. The defaults are conservative on purpose.

| Variable | Default | Notes |
|---|---|---|
| `WEBUI_PASSWORD` | *(generated)* | Password for the sign-in page |
| `WEBUI_SECRET` | *(random)* | Session key. Set it to keep sessions across restarts |
| `WEBUI_PORT` | `8080` | Host port to publish |
| `BRAND_NAME` | `Network Defenders` | Shown in the header and report footer |
| `BRAND_TAGLINE` | `Network Security Assessment` | Sub-heading under the brand name |
| `HTTPS` | `true` | TLS on by default. `false` serves cleartext |
| `TLS_SAN` | *(auto-detected)* | Extra addresses for the certificate |
| `TLS_CERT` / `TLS_KEY` | | Paths to your own certificate and key |
| `SCAN_TYPE` | `auto` | `auto` picks per run, `s` = SYN, `c` = TCP connect |
| `NAABU_TOP_PORTS` | `1000` | Only `100`, `1000`, or `full`. Ignored if `NAABU_PORTS` is set |
| `NAABU_PORTS` | | Explicit list, e.g. `80,443,8080-8090`, or `-` for all 65535 |
| `NAABU_RATE` | `1000` | Packets/sec, used when `SCAN_TYPE` is not `auto` |
| `NAABU_RATE_LOCAL` | `2000` | Rate `auto` uses for directly attached targets |
| `NAABU_RATE_ROUTED` | `300` | Rate `auto` uses when anything is routed |
| `HOST_SUBNETS` | *(auto-detected)* | Directly attached subnets, written by `setup.sh` |
| `NMAP_ARGS` | `-sV -O -Pn -T3` | `-O` guesses the OS; drop it for a faster, quieter scan. Add `-sC` for default scripts, `-T2` to slow down |
| `NUCLEI_SEVERITY` | `info,low,medium,high,critical` | Drop `info` for findings only |
| `NUCLEI_TAGS` | | e.g. `cve,exposure` to narrow the template set |
| `NUCLEI_RATE` | `150` | Requests/sec |
| `NUCLEI_UPDATE` | `false` | `true` refreshes templates before scanning |
| `SKIP_NMAP` / `SKIP_NUCLEI` | `false` | Drop a stage |

`SCAN_TYPE=auto` checks every target against the appliance's own subnets. If all
of them are directly attached it uses SYN scanning at the local rate, since
nothing in between can object. If anything is routed it drops to a connect scan
at the lower rate, because half-open connections through a stateful firewall fill
its state table and get the appliance blocked. Anything ambiguous, including a
name that will not resolve, counts as routed.

Templates are baked into the image, so a fresh appliance scans immediately without
pulling them over the client's network. `docker-compose.yml` caps the container at
2 CPUs and 2 GB. For a Pi-class box, try 1 CPU and 512 MB with `NAABU_RATE=200`.

# Passwords

Each appliance has its own, set at install time. `./setup.sh --prompt` changes it
later. `./setup.sh --password '...'` sets it without prompting, for provisioning
scripts, at the cost of putting it in your shell history.

Keep them in a password manager, one entry per appliance. Do not reuse one
password across sites: anyone who gets it at one client can then log into every
other box you have deployed.

# Deploying to a client site

Full runbook, including the Debian install: **[DEPLOY.md](DEPLOY.md)**.

Confirm written authorization and scope before traveling, verify the certificate
fingerprint on first connect, and clear results before the appliance leaves or is
reused. `output/` holds that client's complete vulnerability map.

```bash
docker compose down && rm -rf output/scan-* certs/
```

`output/` and real target lists are gitignored, so client data cannot reach the
repo. Only scan hosts you have written authorization to test.
