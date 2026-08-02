#!/usr/bin/env python3
"""Web UI for the netscan appliance: launch scans, watch progress, present findings.

Deliberately small — the appliance's whole reason for existing is a low resource
footprint, so this is Flask + the standard library and nothing else.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

OUTPUT_ROOT = Path(os.environ.get("OUTPUT_ROOT", "/output"))
SCAN_SCRIPT = os.environ.get("SCAN_SCRIPT", "/usr/local/bin/scan.sh")
BRAND_NAME = os.environ.get("BRAND_NAME", "Network Defenders")
BRAND_TAGLINE = os.environ.get("BRAND_TAGLINE", "Network Security Assessment")
BRANDING_DIR = Path(os.environ.get("BRANDING_DIR", "/branding"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
HTTPS = os.environ.get("HTTPS", "true").strip().lower() not in ("false", "0", "no", "off")
TLS_SAN = os.environ.get("TLS_SAN", "")
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY = os.environ.get("TLS_KEY", "")
RUN_ID_RE = re.compile(r"^\d{8}-\d{6}$")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}
# Plain-English framing for a non-technical reader.
SEVERITY_MEANING = {
    "critical": "Exploitable now and likely to lead to full system compromise. Address immediately.",
    "high": "A serious weakness that a motivated attacker could use. Address within days.",
    "medium": "A meaningful weakness, usually needing another factor to exploit. Address this cycle.",
    "low": "Minor hardening gaps. Low urgency, worth cleaning up.",
    "info": "Observations about what is running. No action required.",
}

app = Flask(__name__)
app.secret_key = os.environ.get("WEBUI_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Only meaningful under TLS; setting it on plain HTTP would break login.
    SESSION_COOKIE_SECURE=HTTPS,
)

# --------------------------------------------------------------- passwords
#
# Three sources, in order:
#   1. WEBUI_PASSWORD      -- plaintext, for a one-off appliance
#   2. WEBUI_PASSWORD_HASH -- the fleet password, verified against a hash that
#                             ships in the repo. The plaintext never exists in
#                             git, so every appliance authenticates the same
#                             way without anyone typing it at deploy time.
#   3. neither             -- generate one and log it, so the UI is never open.

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def hash_password(pw, salt=None):
    # Fields are ':'-separated, not the conventional '$': this string travels
    # through a .env file that docker compose interpolates, and '$' fields get
    # eaten as undefined variables. ':' never appears in base64.
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt,
                        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{b64(salt)}:{b64(dk)}"


def verify_hash(pw, stored):
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.strip().split(":")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode("utf-8"),
                            salt=base64.b64decode(salt_b64),
                            n=int(n), r=int(r), p=int(p), dklen=32)
        return secrets.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


PASSWORD = os.environ.get("WEBUI_PASSWORD", "")
PASSWORD_HASH = os.environ.get("WEBUI_PASSWORD_HASH", "").strip()
_GENERATED = False
if not PASSWORD and not PASSWORD_HASH:
    # Never leave the UI open: invent a password and print it to the container log.
    PASSWORD = secrets.token_urlsafe(9)
    _GENERATED = True


def check_password(attempt):
    if PASSWORD:
        return secrets.compare_digest(attempt, PASSWORD)
    if PASSWORD_HASH:
        return verify_hash(attempt, PASSWORD_HASH)
    return False

JOBS = {}
JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------- tls

def _host_ips():
    """Addresses this appliance answers on, so the cert matches what you browse to."""
    import socket
    ips = set()
    for probe in (socket.gethostname(), None):
        try:
            for info in socket.getaddrinfo(probe, None, socket.AF_INET):
                ips.add(info[4][0])
        except OSError:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 1))          # TEST-NET-1, no packet is sent
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(i for i in ips if i and not i.startswith("127."))


def build_san():
    parts = ["DNS:localhost", "DNS:netscan-appliance", "IP:127.0.0.1"]
    for ip in _host_ips():
        parts.append("IP:" + ip)
    for raw in TLS_SAN.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if raw.upper().startswith(("IP:", "DNS:")):
            parts.append(raw)
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw):
            parts.append("IP:" + raw)
        else:
            parts.append("DNS:" + raw)
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return ",".join(out)


def ensure_cert():
    """Persist one self-signed cert so its fingerprint is stable and trustable.

    A cert regenerated on every boot can't be trusted once — it would have to be
    re-accepted each start, which trains you to click through warnings.
    """
    if TLS_CERT and TLS_KEY:
        return Path(TLS_CERT), Path(TLS_KEY), False

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    crt, key = CERT_DIR / "appliance.crt", CERT_DIR / "appliance.key"
    sanfile = CERT_DIR / "san.txt"
    san = build_san()

    if crt.exists() and key.exists() and sanfile.exists() \
            and sanfile.read_text().strip() == san:
        return crt, key, False

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "3650",
         "-subj", "/CN=netscan-appliance", "-addext", "subjectAltName=" + san],
        check=True, capture_output=True)
    sanfile.write_text(san)
    os.chmod(key, 0o600)
    return crt, key, True


def fingerprint(crt):
    out = subprocess.run(
        ["openssl", "x509", "-in", str(crt), "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True)
    return out.stdout.strip().split("=", 1)[-1] if out.returncode == 0 else "unavailable"


# ----------------------------------------------------------------- helpers

def utcnow():
    return datetime.now(timezone.utc)


def run_dir_for(run_id):
    if not RUN_ID_RE.match(run_id or ""):
        abort(404)
    d = OUTPUT_ROOT / f"scan-{run_id}"
    if not d.is_dir():
        abort(404)
    return d


def clean_targets(raw):
    """One target per line, comments and stray flags removed."""
    out = []
    for line in (raw or "").replace(",", "\n").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        out.append(line)
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def read_status(run_dir):
    f = run_dir / "status.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            pass
    return {}


def write_status(run_dir, **kw):
    status = read_status(run_dir)
    status.update(kw)
    (run_dir / "status.json").write_text(json.dumps(status, indent=2))
    return status


def stage_from_log(run_dir):
    """Derive human progress from scan.sh's own stage markers."""
    log = run_dir / "scan.log"
    if not log.exists():
        return 0, "Starting"
    text = log.read_text(errors="replace")
    if "stage 3/3" in text:
        return 3, "Checking for vulnerabilities"
    if "stage 2/3" in text:
        return 2, "Identifying services"
    if "stage 1/3" in text:
        return 1, "Discovering open ports"
    return 0, "Starting"


def log_tail(run_dir, n=200):
    log = run_dir / "scan.log"
    if not log.exists():
        return ""
    lines = log.read_text(errors="replace").splitlines()
    # Strip ANSI colour from the tools so the browser shows clean text.
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", ln) for ln in lines[-n:])


# ----------------------------------------------------------------- scanning

def start_scan(targets, opts):
    run_id = utcnow().strftime("%Y%m%d-%H%M%S")
    run_dir = OUTPUT_ROOT / f"scan-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    targets_file = run_dir / "targets.input"
    targets_file.write_text("\n".join(targets) + "\n")

    env = os.environ.copy()
    env["RUN_ID"] = run_id
    env["TARGETS_FILE"] = str(targets_file)
    env.pop("TARGET", None)
    env.update({k: str(v) for k, v in opts.items() if v not in (None, "")})

    write_status(run_dir, state="running", started=utcnow().isoformat(),
                 targets=len(targets), client=opts.get("_client", ""),
                 profile=opts.get("_profile", ""))

    logf = open(run_dir / "scan.log", "wb")
    proc = subprocess.Popen([SCAN_SCRIPT], env=env, stdout=logf,
                            stderr=subprocess.STDOUT, cwd="/")

    def waiter():
        rc = proc.wait()
        logf.close()
        write_status(run_dir, state="done" if rc == 0 else "failed",
                     finished=utcnow().isoformat(), exit_code=rc)
        with JOBS_LOCK:
            JOBS.pop(run_id, None)

    threading.Thread(target=waiter, daemon=True).start()
    with JOBS_LOCK:
        JOBS[run_id] = proc
    return run_id


# ----------------------------------------------------------------- parsing

def parse_hosts(run_dir):
    """Open ports from naabu, enriched with nmap service/version detail."""
    hosts = {}
    naabu = run_dir / "naabu.json"
    if naabu.exists():
        for line in naabu.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            ip = d.get("ip") or d.get("host")
            if not ip:
                continue
            hosts.setdefault(ip, {})[int(d.get("port", 0))] = {
                "port": int(d.get("port", 0)), "service": "", "product": ""}

    for xml in sorted((run_dir / "nmap").glob("*.xml")) if (run_dir / "nmap").is_dir() else []:
        try:
            root = ET.parse(xml).getroot()
        except (ET.ParseError, OSError):
            continue
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            for p in host.findall(".//port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                pn = int(p.get("portid"))
                svc = p.find("service")
                entry = hosts.setdefault(ip, {}).setdefault(
                    pn, {"port": pn, "service": "", "product": ""})
                if svc is not None:
                    entry["service"] = svc.get("name") or ""
                    entry["product"] = " ".join(
                        x for x in [svc.get("product"), svc.get("version")] if x)

    return {ip: sorted(ports.values(), key=lambda e: e["port"])
            for ip, ports in sorted(hosts.items())}


def parse_findings(run_dir):
    """Group nuclei matches by template so a report lists issues, not events."""
    path = run_dir / "nuclei.jsonl"
    groups = {}
    if not path.exists():
        return []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        info = d.get("info") or {}
        tid = d.get("template-id") or "unknown"
        sev = (info.get("severity") or "info").lower()
        if sev not in SEVERITY_ORDER:
            sev = "info"
        g = groups.setdefault(tid, {
            "id": tid,
            "name": info.get("name") or tid,
            "severity": sev,
            "description": (info.get("description") or "").strip(),
            "remediation": (info.get("remediation") or "").strip(),
            "tags": info.get("tags") or [],
            "assets": set(),
        })
        asset = d.get("matched-at") or d.get("host") or ""
        if asset:
            g["assets"].add(asset)

    out = []
    for g in groups.values():
        g["assets"] = sorted(g["assets"])
        out.append(g)
    out.sort(key=lambda g: (SEVERITY_ORDER.index(g["severity"]), -len(g["assets"]),
                            g["name"].lower()))
    return out


def build_report(run_id):
    run_dir = run_dir_for(run_id)
    status = read_status(run_dir)
    hosts = parse_hosts(run_dir)
    findings = parse_findings(run_dir)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    actionable = sum(counts[s] for s in ("critical", "high", "medium", "low"))
    highest = next((s for s in SEVERITY_ORDER if counts[s]), None)
    # 'info' findings are inventory, not risk — they must not drive the headline.
    if highest == "info":
        highest = None

    scope = []
    tf = run_dir / "targets.input"
    if not tf.exists():
        tf = run_dir / "targets.txt"
    if tf.exists():
        scope = [l for l in tf.read_text(errors="replace").splitlines() if l.strip()]

    return {
        "run_id": run_id,
        "status": status,
        "hosts": hosts,
        "findings": findings,
        "counts": counts,
        "actionable": actionable,
        "highest": highest,
        "scope": scope,
        "total_services": sum(len(v) for v in hosts.values()),
        "started": status.get("started", ""),
        "client": status.get("client", ""),
    }


def reap_orphaned_runs():
    """Mark scans that died with a previous container.

    A restart kills any in-flight scan along with the thread that would have
    recorded the outcome, so without this the run shows 'running' forever and
    the progress page spins indefinitely.
    """
    if not OUTPUT_ROOT.is_dir():
        return
    for d in OUTPUT_ROOT.glob("scan-*"):
        if d.is_dir() and read_status(d).get("state") == "running":
            write_status(d, state="interrupted", finished=utcnow().isoformat(),
                         note="The appliance restarted while this scan was running.")


def list_scans():
    rows = []
    for d in sorted(OUTPUT_ROOT.glob("scan-*"), reverse=True):
        if not d.is_dir():
            continue
        run_id = d.name.replace("scan-", "", 1)
        if not RUN_ID_RE.match(run_id):
            continue
        st = read_status(d)
        nuclei = d / "nuclei.jsonl"
        n_find = 0
        if nuclei.exists():
            n_find = sum(1 for l in nuclei.read_text(errors="replace").splitlines() if l.strip())
        rows.append({
            "run_id": run_id,
            "state": st.get("state", "done"),
            "client": st.get("client", ""),
            "started": st.get("started", ""),
            "findings": n_find,
        })
    return rows[:40]


# ----------------------------------------------------------------- routes

@app.before_request
def guard():
    if request.endpoint in ("login", "static"):
        return None
    if not session.get("auth"):
        return redirect(url_for("login", next=request.path))
    return None


def logo_path():
    """Drop a real logo at /branding/logo.png to replace the built-in mark."""
    for name in ("logo.png", "logo.jpg", "logo.jpeg", "logo.svg", "logo.webp"):
        p = BRANDING_DIR / name
        if p.is_file():
            return p
    return None


@app.route("/branding/logo")
def branding_logo():
    p = logo_path()
    if not p:
        abort(404)
    return send_file(str(p))


@app.context_processor
def inject_brand():
    return {"brand_name": BRAND_NAME, "brand_tagline": BRAND_TAGLINE,
            "brand_logo": logo_path() is not None,
            "sev_order": SEVERITY_ORDER, "sev_label": SEVERITY_LABEL,
            "sev_meaning": SEVERITY_MEANING}


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if check_password(request.form.get("password", "")):
            session["auth"] = True
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") else url_for("index"))
        error = "Incorrect password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html", scans=list_scans())


@app.route("/scan", methods=["POST"])
def scan():
    targets = clean_targets(request.form.get("targets", ""))
    if not targets:
        return render_template("index.html", scans=list_scans(),
                               error="Enter at least one target address or range."), 400

    profile = request.form.get("profile", "standard")
    opts = {"_client": request.form.get("client", "").strip(), "_profile": profile}
    if profile == "quick":
        opts.update({"NAABU_TOP_PORTS": "100", "SKIP_NUCLEI": "true"})
    elif profile == "gentle":
        opts.update({"NAABU_TOP_PORTS": "1000", "NAABU_RATE": "200",
                     "NUCLEI_CONCURRENCY": "10", "NMAP_ARGS": "-sV -Pn -T2"})
    elif profile == "thorough":
        opts.update({"NAABU_TOP_PORTS": "full"})
    else:
        opts.update({"NAABU_TOP_PORTS": "1000"})

    run_id = start_scan(targets, opts)
    return redirect(url_for("scan_view", run_id=run_id))


@app.route("/scan/<run_id>")
def scan_view(run_id):
    run_dir = run_dir_for(run_id)
    return render_template("scan.html", run_id=run_id, status=read_status(run_dir))


@app.route("/api/scan/<run_id>")
def api_scan(run_id):
    run_dir = run_dir_for(run_id)
    status = read_status(run_dir)
    stage, label = stage_from_log(run_dir)
    return jsonify({"state": status.get("state", "done"), "stage": stage,
                    "label": label, "log": log_tail(run_dir),
                    "exit_code": status.get("exit_code")})


@app.route("/report/<run_id>")
def report(run_id):
    return render_template("report.html", r=build_report(run_id))


if __name__ == "__main__":
    # `app.py --hash` prints a fleet password hash to commit to the repo.
    if "--hash" in sys.argv:
        pw = os.environ.get("FLEET_PASSWORD", "")
        if not pw:
            import getpass
            pw = getpass.getpass("Fleet password: ") if sys.stdin.isatty() \
                else sys.stdin.readline().rstrip("\n")
        if not pw:
            print("No password given.", file=sys.stderr)
            raise SystemExit(1)
        print(hash_password(pw))
        raise SystemExit(0)

    reap_orphaned_runs()

    port = int(os.environ.get("WEBUI_PORT", "8080"))
    ssl_context = None
    line = "=" * 68

    if HTTPS:
        crt, key, created = ensure_cert()
        ssl_context = (str(crt), str(key))
        print(line, flush=True)
        print(f"  HTTPS enabled ({'new certificate generated' if created else 'reusing stored certificate'})", flush=True)
        print(f"  SHA-256 fingerprint:  {fingerprint(crt)}", flush=True)
        print("  Compare this against the certificate your browser shows the", flush=True)
        print("  first time, then trust it. A mismatch later means someone is", flush=True)
        print("  intercepting the connection.", flush=True)
        print(f"  URL:  https://<appliance-ip>:{port}/", flush=True)
        print(line, flush=True)
    else:
        print(line, flush=True)
        print("  WARNING: HTTPS is disabled. The password and every scan finding", flush=True)
        print("  will cross the network in cleartext. Set HTTPS=true.", flush=True)
        print(line, flush=True)

    if _GENERATED:
        print("  No WEBUI_PASSWORD set. Generated one for this session:", flush=True)
        print(f"     {PASSWORD}", flush=True)
        print("  Set WEBUI_PASSWORD in .env to pin your own.", flush=True)
        print(line, flush=True)

    app.run(host=os.environ.get("WEBUI_BIND", "0.0.0.0"), port=port,
            threaded=True, ssl_context=ssl_context)
