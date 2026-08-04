#!/usr/bin/env python3
"""Web UI for the netscan appliance: launch scans, watch progress, present findings.

Kept small: the appliance's whole reason for existing is a low resource
footprint, so this is Flask + the standard library and nothing else.
"""
import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

OUTPUT_ROOT = Path(os.environ.get("OUTPUT_ROOT", "/output"))
SCAN_SCRIPT = os.environ.get("SCAN_SCRIPT", "/usr/local/bin/scan.sh")
BRAND_NAME = os.environ.get("BRAND_NAME", "Network Defenders")
BRAND_TAGLINE = os.environ.get("BRAND_TAGLINE", "Network Security Assessment")
BRANDING_DIR = Path(os.environ.get("BRANDING_DIR", "/branding"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
TEMPLATE_DIR = Path(os.environ.get("NUCLEI_TEMPLATE_DIR", "/root/nuclei-templates"))
HOST_SUBNETS = os.environ.get("HOST_SUBNETS", "")
BUILD_REF = os.environ.get("BUILD_REF", "")
BUILD_DATE = os.environ.get("BUILD_DATE", "")
UPDATE_CHECK_URL = os.environ.get("UPDATE_CHECK_URL", "").strip()
HTTPS = os.environ.get("HTTPS", "true").strip().lower() not in ("false", "0", "no", "off")
TLS_SAN = os.environ.get("TLS_SAN", "")
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY = os.environ.get("TLS_KEY", "")
RUN_ID_RE = re.compile(r"^\d{8}-\d{6}$")

# Recurring scans. Schedules are plain JSON under /output, so they survive
# container restarts and never leak client data into the repository.
SCHEDULE_FILE = Path(os.environ.get("SCHEDULE_FILE", "/output/schedules.json"))
SCHEDULE_KINDS = ["daily", "weekly", "interval"]
WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEKDAY_LABEL = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday",
                 "thu": "Thursday", "fri": "Friday", "sat": "Saturday",
                 "sun": "Sunday"}

# Nessus maps severities onto a 0-4 integer scale; 0 is informational.
NESSUS_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

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

# scan.sh skips active probing (nmap -sV, nuclei) on these -- kept in sync
# with scan.sh's own default for NOPROBE_PORTS. Two different reasons land a
# port here: raw printing has no request/response framing, so a probe payload
# is printed verbatim; the ICS/building-automation ports are fragile enough
# that ordinary scan traffic has been documented to crash or hang them.
RAW_PRINT_PORTS = {9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 515}
ICS_PORTS = {502, 102, 47808, 44818, 20000}

RAW_PORT_LABELS = {
    9100: "raw printing (JetDirect/AppSocket)",
    9101: "raw printing (JetDirect/AppSocket)",
    9102: "raw printing (JetDirect/AppSocket)",
    9103: "raw printing (JetDirect/AppSocket)",
    9104: "raw printing (JetDirect/AppSocket)",
    9105: "raw printing (JetDirect/AppSocket)",
    9106: "raw printing (JetDirect/AppSocket)",
    9107: "raw printing (JetDirect/AppSocket)",
    515: "LPD printing",
    502: "Modbus TCP (industrial control)",
    102: "Siemens S7comm (industrial control)",
    47808: "BACnet/IP (building automation)",
    44818: "EtherNet/IP CIP (industrial control)",
    20000: "DNP3 (industrial control / utility SCADA)",
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
# The password is chosen at install time and lives in .env. If none is set we
# generate one and log it, so the UI is never left open.

PASSWORD = os.environ.get("WEBUI_PASSWORD", "")
_GENERATED = False
if not PASSWORD:
    PASSWORD = secrets.token_urlsafe(9)
    _GENERATED = True


def check_password(attempt):
    return bool(PASSWORD) and secrets.compare_digest(attempt, PASSWORD)

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
    parts = ["DNS:localhost", "DNS:nd-scanner", "IP:127.0.0.1"]
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

    A cert regenerated on every boot can't be trusted once. It would have to be
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
         "-subj", "/CN=nd-scanner", "-addext", "subjectAltName=" + san],
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


def scan_progress(run_dir):
    """Live counts for the progress page.

    Read from the artefacts the tools are writing rather than by scraping the
    log, so the numbers match what ends up in the report.
    """
    # naabu only writes naabu.json when the stage ends, but it prints each hit
    # as it goes, so the log is the only live source during discovery. Merge
    # both and de-duplicate, so the count climbs during the stage and does not
    # jump or regress when the file finally appears.
    found = set()

    def collect(text):
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{") or '"port"' not in line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if "template-id" in d:      # a nuclei finding, not a naabu hit
                continue
            ip = d.get("ip") or d.get("host")
            port = d.get("port")
            if ip and port is not None:
                found.add((ip, int(port)))

    naabu = run_dir / "naabu.json"
    if naabu.exists():
        collect(naabu.read_text(errors="replace"))
    log_file = run_dir / "scan.log"
    if log_file.exists():
        collect(log_file.read_text(errors="replace"))

    hosts = {ip for ip, _ in found}
    ports = len(found)

    nmap_dir = run_dir / "nmap"
    services = len(list(nmap_dir.glob("*.xml"))) if nmap_dir.is_dir() else 0

    # Grouped by template like parse_findings(), but severity "info" is
    # inventory (what's running), not a vulnerability, so it is excluded here
    # -- same definition as the finished report's "Issues to address" tile.
    # The findings dropdown intentionally keeps every severity; this is a
    # narrower, actionable-only count for a quick glance while a scan runs.
    vulnerabilities = sum(1 for f in parse_findings(run_dir) if f["severity"] != "info")

    vanished, checked = count_vanished_ports(run_dir)
    # A scan being blocked mid-run looks identical to a clean result unless
    # something is surfaced while it runs. nuclei's own error rate does not
    # work for this: it fires HTTP templates at every open port regardless of
    # protocol, so a normal mix of SSH, SMB and RPC services produces a high
    # error rate with nothing wrong. Comparing naabu against nmap does not
    # have that problem, because both are asking the same yes/no question
    # (is this port open) rather than "does this respond like a web server".
    unreachable = round(100 * vanished / checked) if checked else 0

    return {
        "hosts": len(hosts),
        "ports": ports,
        "services": services,
        "vulnerabilities": vulnerabilities,
        "unreachable": unreachable,
        "degraded": checked >= 5 and unreachable >= 20,
    }


def count_vanished_ports(run_dir):
    """Ports naabu found open that nmap, moments later, did not.

    naabu and nmap ask the same question of the same port within seconds of
    each other, so unlike nuclei's HTTP probing this is not sensitive to what
    protocol the service actually speaks. A port that goes from open to
    filtered or closed in that window means something started dropping or
    resetting the connection between the two passes, which is a stronger
    signal than a raw error count.
    """
    nmap_dir = run_dir / "nmap"
    if not nmap_dir.is_dir():
        return 0, 0

    # nmap -oA writes a host's XML only once it has finished every port for
    # that host, so a host with no XML file yet has simply not been reached --
    # it has not "vanished". Judging it before nmap gets there produced a
    # false 100% on a single-host scan: naabu.json is written the moment
    # naabu finishes, well before nmap's one XML file lands, so every port
    # briefly looked unconfirmed even though nothing was wrong.
    confirmed_open = set()
    completed_hosts = set()
    for xml_path in nmap_dir.glob("*.xml"):
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, OSError):
            continue
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            completed_hosts.add(ip)
            for p in host.findall(".//port"):
                st = p.find("state")
                if st is not None and st.get("state") == "open":
                    confirmed_open.add((ip, int(p.get("portid"))))

    naabu = run_dir / "naabu.json"
    if not naabu.exists():
        return 0, 0
    naabu_open = set()
    for line in naabu.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        ip = d.get("ip") or d.get("host")
        if ip and d.get("port") is not None:
            naabu_open.add((ip, int(d["port"])))

    # Ports scan.sh deliberately never handed to nmap (raw/print ports) will
    # never show up as "confirmed" -- that is by design, not a sign the scan
    # was blocked, so they must not count toward vanished/checkable.
    noprobe = run_dir / "noprobe.tsv"
    if noprobe.exists():
        for line in noprobe.read_text(errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 2:
                continue
            ip, port_s = parts
            try:
                naabu_open.discard((ip, int(port_s)))
            except ValueError:
                pass

    checkable = {pair for pair in naabu_open if pair[0] in completed_hosts}
    if not checkable:
        return 0, 0
    vanished = len(checkable - confirmed_open)
    return vanished, len(checkable)


def log_tail(run_dir, n=200):
    log = run_dir / "scan.log"
    if not log.exists():
        return ""
    lines = log.read_text(errors="replace").splitlines()
    # Strip ANSI color from the tools so the browser shows clean text.
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", ln) for ln in lines[-n:])


# ----------------------------------------------------------------- scanning

def profile_opts(profile):
    """Map a UI profile name onto the scan-knob overrides it implies.

    Shared by the manual scan form and the scheduler so a scheduled run of the
    same profile behaves identically to one launched by hand.
    """
    profile = profile or "standard"
    if profile == "quick":
        return {"NAABU_TOP_PORTS": "100", "SKIP_NUCLEI": "true"}
    if profile == "gentle":
        return {"NAABU_TOP_PORTS": "1000", "NAABU_RATE": "200",
                "NUCLEI_CONCURRENCY": "10", "NMAP_ARGS": "-sV -Pn -T2"}
    if profile == "thorough":
        return {"NAABU_TOP_PORTS": "full"}
    return {"NAABU_TOP_PORTS": "1000"}


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
                 profile=opts.get("_profile", ""),
                 _schedule=opts.get("_schedule", ""),
                 avoid_fragile_ics=opts.get("AVOID_FRAGILE_ICS", "true"))

    logf = open(run_dir / "scan.log", "wb")
    # New session, so the whole tool chain can be signaled as one group:
    # killing scan.sh alone would leave naabu or nmap running.
    proc = subprocess.Popen([SCAN_SCRIPT], env=env, stdout=logf,
                            stderr=subprocess.STDOUT, cwd="/",
                            start_new_session=True)

    def waiter():
        rc = proc.wait()
        logf.close()
        # A cancelled run has already recorded why it ended; a non-zero exit is
        # the expected consequence, not a failure to report.
        if read_status(run_dir).get("state") != "cancelled":
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
    """Open ports from naabu, enriched with nmap's service, hostname and OS detail.

    Returns {ip: {"hostname": str, "os": str, "ports": [...]}}. hostname and os
    are best-effort and often empty -- a device with no PTR record or that
    nmap cannot fingerprint confidently simply has nothing to show, which is
    preferable to guessing.
    """
    hosts = {}

    def host_entry(ip):
        return hosts.setdefault(ip, {"hostname": "", "os": "", "ports": {}})

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
            pn = int(d.get("port", 0))
            host_entry(ip)["ports"][pn] = {
                "port": pn, "service": "", "product": "", "extrainfo": ""}

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
            entry = host_entry(ip)

            hn_el = host.find("hostnames")
            if hn_el is not None and not entry["hostname"]:
                names = hn_el.findall("hostname")
                ptr = next((n for n in names if n.get("type") == "PTR"), None)
                chosen = ptr or (names[0] if names else None)
                if chosen is not None and chosen.get("name"):
                    entry["hostname"] = chosen.get("name")

            os_el = host.find("os")
            if os_el is not None and not entry["os"]:
                matches = os_el.findall("osmatch")
                if matches:
                    best = max(matches, key=lambda m: int(m.get("accuracy", 0)))
                    entry["os"] = f'{best.get("name")} ({best.get("accuracy")}% confidence)'

            for p in host.findall(".//port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                pn = int(p.get("portid"))
                svc = p.find("service")
                pentry = entry["ports"].setdefault(
                    pn, {"port": pn, "service": "", "product": "", "extrainfo": ""})
                if svc is not None:
                    pentry["service"] = svc.get("name") or ""
                    pentry["product"] = " ".join(
                        x for x in [svc.get("product"), svc.get("version")] if x)
                    pentry["extrainfo"] = svc.get("extrainfo") or ""

    noprobe = run_dir / "noprobe.tsv"
    if noprobe.exists():
        for line in noprobe.read_text(errors="replace").splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 2:
                continue
            ip, port_s = parts
            try:
                pn = int(port_s)
            except ValueError:
                continue
            pentry = host_entry(ip)["ports"].setdefault(
                pn, {"port": pn, "service": "", "product": "", "extrainfo": ""})
            pentry["service"] = RAW_PORT_LABELS.get(pn, "raw/unprobed")
            pentry["product"] = "not actively probed"
            if pn in ICS_PORTS:
                pentry["extrainfo"] = "documented to crash or hang on ordinary scan traffic, so probing is skipped"
            else:
                pentry["extrainfo"] = "sends any bytes it receives straight to output, so probing is skipped"

    out = {}
    for ip, h in sorted(hosts.items()):
        h["ports"] = sorted(h["ports"].values(), key=lambda e: e["port"])
        out[ip] = h
    return out


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
            "ips": set(),
        })
        asset = d.get("matched-at") or d.get("host") or ""
        if asset:
            g["assets"].add(asset)
        # Kept separate from "assets": matched-at is a display string (a full
        # URL, often), not reliably an IP to key host lookups against, but
        # nuclei's own "ip" field always is.
        ip = d.get("ip") or d.get("host") or ""
        if ip:
            g["ips"].add(ip)

    out = []
    for g in groups.values():
        g["assets"] = sorted(g["assets"])
        g["ips"] = sorted(g["ips"])
        out.append(g)
    out.sort(key=lambda g: (SEVERITY_ORDER.index(g["severity"]), -len(g["assets"]),
                            g["name"].lower()))
    return out


def raw_port_findings(run_dir):
    """Synthesized findings covering ports scan.sh deliberately never probed
    (see NOPROBE_PORTS in scan.sh). Their exposure is that they answer at all
    -- an actual version/vulnerability probe would itself trigger the crash or
    the unwanted behavior being avoided, which is why nmap and nuclei never
    touch them. Raw printing and fragile ICS ports get separate findings
    because the risk and the fix are different.
    """
    noprobe = run_dir / "noprobe.tsv"
    if not noprobe.exists():
        return []

    groups = {"print": {"assets": set(), "ips": set()}, "ics": {"assets": set(), "ips": set()}}
    for line in noprobe.read_text(errors="replace").splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 2:
            continue
        ip, port_s = parts
        try:
            pn = int(port_s)
        except ValueError:
            continue
        key = "ics" if pn in ICS_PORTS else "print"
        groups[key]["assets"].add(f"{ip}:{port_s}")
        groups[key]["ips"].add(ip)

    out = []
    if groups["print"]["assets"]:
        out.append({
            "id": "raw-print-port-exposed",
            "name": "Raw printing/serial port reachable without restriction",
            "severity": "medium",
            "description": (
                "This port has no request/response protocol: any data sent to it "
                "is acted on directly, most often printed verbatim by the device "
                "on the other end. It was not tested directly because a version "
                "or vulnerability probe would itself trigger that behavior -- the "
                "exposure is that it answers at all. Anyone who can reach it, "
                "including a workstation elsewhere on the network that has "
                "already been compromised, can print arbitrary documents, "
                "intercept or replay print jobs, or exhaust paper and toner as a "
                "denial of service."
            ),
            "remediation": (
                "Restrict reachability rather than the service itself: place "
                "printers and similar raw-port devices on a dedicated VLAN "
                "reachable only by an authorized print server (or the specific "
                "hosts that need it), not the general user network. Prefer an "
                "authenticated printing path, such as IPP over TLS through a "
                "managed print server, over exposing the raw port directly, and "
                "disable the port if it is not in active use."
            ),
            "tags": ["exposure", "network-segmentation"],
            "assets": sorted(groups["print"]["assets"]),
            "ips": sorted(groups["print"]["ips"]),
        })
    if groups["ics"]["assets"]:
        out.append({
            "id": "fragile-ics-port-exposed",
            "name": "Industrial control / building-automation port reachable without restriction",
            "severity": "high",
            "description": (
                "This port belongs to an industrial control or building-"
                "automation protocol (Modbus, Siemens S7comm, BACnet/IP, "
                "EtherNet/IP, or DNP3). These devices are documented to crash or "
                "hang from ordinary scan traffic -- small connection tables and "
                "minimal input validation mean even a routine version-detection "
                "probe can take the device offline, so it was not tested "
                "directly. The exposure itself is serious: if this network "
                "segment is reachable from general office IT, a compromised "
                "workstation could reach and disrupt physical equipment (HVAC, "
                "manufacturing, access control, or utility gear) with no "
                "authentication required."
            ),
            "remediation": (
                "This almost always means IT and OT networks are not properly "
                "separated. Put control-system devices on an isolated VLAN with "
                "a firewall between it and the general network, allowing only "
                "the specific engineering workstations and historian/SCADA "
                "servers that need access. Do not rely on this scanner, or any "
                "general-purpose IT scanner, to assess these devices further -- "
                "use an OT-aware tool, and only during a maintenance window."
            ),
            "tags": ["exposure", "network-segmentation", "ics"],
            "assets": sorted(groups["ics"]["assets"]),
            "ips": sorted(groups["ics"]["ips"]),
        })
    return out


def ip_sort_key(ip):
    """Numeric, not lexicographic: string-sorting IPs puts 10.1.20.100 before
    10.1.20.36 before 10.1.20.9, which is not the order a reader expects."""
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def attach_host_findings(hosts, findings):
    """Each host's own vulnerabilities, condensed to name + severity.

    Full description and remediation stay in the severity-grouped section --
    repeating them per host would blow up a report where one issue affects
    many machines. This is a pointer back to that detail, scoped to one
    system, for whoever is responsible for just that box.
    """
    for h in hosts.values():
        h["findings"] = []
        h["sev_counts"] = {s: 0 for s in SEVERITY_ORDER}

    for f in findings:
        for ip in f["ips"]:
            h = hosts.get(ip)
            if h is None:
                continue
            h["findings"].append({"name": f["name"], "severity": f["severity"]})
            h["sev_counts"][f["severity"]] += 1

    for h in hosts.values():
        h["findings"].sort(key=lambda x: SEVERITY_ORDER.index(x["severity"]))

    def risk_key(item):
        ip, h = item
        worst = (min(SEVERITY_ORDER.index(x["severity"]) for x in h["findings"])
                if h["findings"] else len(SEVERITY_ORDER))
        return (worst, -len(h["findings"]), ip_sort_key(ip))

    return dict(sorted(hosts.items(), key=risk_key))


def build_report(run_id):
    run_dir = run_dir_for(run_id)
    status = read_status(run_dir)
    hosts = parse_hosts(run_dir)
    findings = parse_findings(run_dir) + raw_port_findings(run_dir)
    findings.sort(key=lambda g: (SEVERITY_ORDER.index(g["severity"]), -len(g["assets"]),
                                 g["name"].lower()))
    hosts = attach_host_findings(hosts, findings)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    actionable = sum(counts[s] for s in ("critical", "high", "medium", "low"))
    highest = next((s for s in SEVERITY_ORDER if counts[s]), None)
    # 'info' findings are inventory, not risk, so they must not drive the headline.
    if highest == "info":
        highest = None

    scope = []
    tf = run_dir / "targets.input"
    if not tf.exists():
        tf = run_dir / "targets.txt"
    if tf.exists():
        scope = [l for l in tf.read_text(errors="replace").splitlines() if l.strip()]

    progress = scan_progress(run_dir)

    return {
        "unreachable": progress["unreachable"],
        "degraded": progress["degraded"],
        "run_id": run_id,
        "status": status,
        "hosts": hosts,
        "findings": findings,
        "counts": counts,
        "actionable": actionable,
        "highest": highest,
        "scope": scope,
        "total_services": sum(len(v["ports"]) for v in hosts.values()),
        "started": status.get("started", ""),
        "client": status.get("client", ""),
    }


# -------------------------------------------------------------- exporting

EXPORT_FORMATS = ["html", "csv", "json", "nessus"]
EXPORT_LABEL = {"html": "HTML report", "csv": "CSV spreadsheets",
                "json": "Structured JSON", "nessus": "Nessus XML"}


def _xml_clean(text):
    """Drop bytes XML 1.0 cannot represent (control chars etc.)."""
    if not text:
        return ""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch in "\t\n\r" or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD:
            out.append(ch)
    return "".join(out)


def _plugin_id(tid):
    """Stable numeric id for a template, for tools that want a number.

    Python's built-in hash is randomised per process, so it cannot be used
    here -- the same report must map to the same id every time it is exported.
    """
    digest = hashlib.md5(tid.encode("utf-8", "replace")).hexdigest()
    return str(int(digest[:8], 16))


def inventory_csv_text(r):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "hostname", "os", "port", "protocol", "service",
                "software", "extrainfo"])
    for ip, host in r["hosts"].items():
        for p in host["ports"]:
            w.writerow([ip, host.get("hostname", ""), host.get("os", ""),
                        p["port"], "tcp", p.get("service", ""),
                        p.get("product", ""), p.get("extrainfo", "")])
    return buf.getvalue()


def findings_csv_text(r):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "name", "template_id", "host", "assets",
                "description", "remediation"])
    for f in r["findings"]:
        ips = f.get("ips") or [""]
        assets = "; ".join(f.get("assets") or [])
        for ip in ips:
            w.writerow([f["severity"], f["name"], f["id"], ip, assets,
                        f.get("description", ""), f.get("remediation", "")])
    return buf.getvalue()


def report_json_text(r):
    return json.dumps(r, indent=2, ensure_ascii=False)


def nessus_xml(r):
    """A Nessus v2 document so results import into Tenable and its ecosystem."""
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name=f"nd-scanner {r['run_id']}")

    for ip, host in r["hosts"].items():
        rhost = ET.SubElement(report, "ReportHost", name=ip)
        props = ET.SubElement(rhost, "HostProperties")
        if host.get("hostname"):
            ET.SubElement(props, "tag", name="host-fqdn").text = host["hostname"]
        ET.SubElement(props, "tag", name="host-ip").text = ip
        if host.get("os"):
            ET.SubElement(props, "tag", name="operating-system").text = host["os"]
        ET.SubElement(props, "tag", name="mac-address").text = ""
        ET.SubElement(props, "tag", name="HOST_START").text = r["started"]
        ET.SubElement(props, "tag", name="HOST_END").text = r["started"]

        # Every open port as an informational item, so the import carries the
        # full inventory even for hosts with no vulnerabilities.
        for p in host["ports"]:
            item = ET.SubElement(rhost, "ReportItem", port=str(p["port"]),
                                 svc_name=p.get("service") or "unknown",
                                 protocol="tcp", severity="0",
                                 pluginID=_plugin_id(f"port-{p['port']}"),
                                 pluginName="Open port",
                                 pluginFamily="Port scanning")
            ET.SubElement(item, "description").text = (
                f"Port {p['port']}/tcp is open and reachable.")
            svc = " ".join(x for x in (p.get("service"), p.get("product")) if x)
            if svc:
                ET.SubElement(item, "plugin_output").text = f"Service: {svc}"

        for f in r["findings"]:
            sev = NESSUS_SEVERITY.get(f["severity"], 0)
            item = ET.SubElement(
                rhost, "ReportItem", port="0", svc_name="general",
                protocol="tcp", severity=str(sev),
                pluginID=_plugin_id(f["id"]),
                pluginName=_xml_clean(f["name"]) or f["id"],
                pluginFamily=f["severity"].title())
            if f.get("description"):
                ET.SubElement(item, "description").text = _xml_clean(f["description"])
            if f.get("remediation"):
                ET.SubElement(item, "solution").text = _xml_clean(f["remediation"])
            if f.get("ips"):
                ET.SubElement(item, "plugin_output").text = (
                    "Affected hosts: " + ", ".join(sorted(f["ips"])))
            ET.SubElement(item, "cvss_base_score").text = "0.0"
            ET.SubElement(item, "cve").text = ""

    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0"?>\n' + body + "\n"


def export_archive(run_ids, fmt):
    """A zip of one or more runs in a single format.

    Called by the bulk export route. "html" keeps the current behaviour of a
    standalone, self-contained report per run; the other formats are machine
    readable so results feed straight into other tooling.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rid in run_ids:
            r = build_report(rid)
            client = (r.get("client") or "").strip()
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", client).strip("_") or "report"
            stem = f"{safe}-{rid}"
            if fmt == "html":
                zf.writestr(f"{stem}.html", render_standalone_report(rid))
            elif fmt == "csv":
                zf.writestr(f"{stem}-inventory.csv", inventory_csv_text(r))
                zf.writestr(f"{stem}-findings.csv", findings_csv_text(r))
            elif fmt == "json":
                zf.writestr(f"{stem}.json", report_json_text(r))
            else:  # nessus
                zf.writestr(f"{stem}.nessus", nessus_xml(r))
    buf.seek(0)
    return buf


def report_export_bytes(fmt, rid):
    r = build_report(rid)
    if fmt == "json":
        return report_json_text(r).encode("utf-8"), "application/json"
    if fmt == "nessus":
        return nessus_xml(r).encode("utf-8"), "application/xml"
    return render_standalone_report(rid).encode("utf-8"), "text/html"


# ---------------------------------------------------------------- diffing

def port_set(hosts):
    """{ip: {port, ...}} -- what was open where, per run."""
    return {ip: {p["port"] for p in h["ports"]} for ip, h in hosts.items()}


def compare_runs(baseline_id, comparison_id):
    """Everything that changed between two scans.

    Direction matters: "new" means present in the comparison run but not the
    baseline, so the baseline should be the older scan and the comparison the
    newer one. Comparing scans of different networks produces a mostly-meaningless
    "everything changed" and is the operator's call, not something to prevent.
    """
    b_dir = run_dir_for(baseline_id)
    c_dir = run_dir_for(comparison_id)
    b_status = read_status(b_dir)
    c_status = read_status(c_dir)

    hosts_b = parse_hosts(b_dir)
    hosts_c = parse_hosts(c_dir)
    ports_b = port_set(hosts_b)
    ports_c = port_set(hosts_c)

    findings_b = {f["id"]: f for f in parse_findings(b_dir)}
    findings_c = {f["id"]: f for f in parse_findings(c_dir)}

    def find_count(findings):
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings.values():
            counts[f["severity"]] += 1
        return counts

    all_ips = set(ports_b) | set(ports_c)
    host_rows = []
    for ip in sorted(all_ips, key=ip_sort_key):
        pa, pc = ports_b.get(ip, set()), ports_c.get(ip, set())
        hb, hc = hosts_b.get(ip, {}), hosts_c.get(ip, {})
        new_ports = sorted(pc - pa)
        closed_ports = sorted(pa - pc)
        if not new_ports and not closed_ports:
            continue
        host_rows.append({
            "ip": ip,
            "hostname": hc.get("hostname") or hb.get("hostname", ""),
            "present_baseline": ip in ports_b,
            "present_comparison": ip in ports_c,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
        })
    host_rows.sort(key=lambda r: (r["present_baseline"] != r["present_comparison"],
                                  -len(r["new_ports"]) - len(r["closed_ports"]),
                                  ip_sort_key(r["ip"])))

    new_hosts = [r for r in host_rows if not r["present_baseline"] and r["present_comparison"]]
    gone_hosts = [r for r in host_rows if r["present_baseline"] and not r["present_comparison"]]

    new_findings = []
    for tid, f in findings_c.items():
        if tid not in findings_b:
            new_findings.append(f)
    new_findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["name"].lower()))

    resolved_findings = []
    for tid, f in findings_b.items():
        if tid not in findings_c:
            resolved_findings.append(f)
    resolved_findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["name"].lower()))

    changed_findings = []
    for tid, f in findings_c.items():
        prev = findings_b.get(tid)
        if prev is None:
            continue
        ca, ra = set(f.get("assets") or []), set(prev.get("assets") or [])
        added, removed = sorted(ca - ra), sorted(ra - ca)
        if added or removed:
            changed_findings.append({
                "id": tid,
                "name": f["name"],
                "severity": f["severity"],
                "added": added,
                "removed": removed,
            })
    changed_findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["name"].lower()))

    return {
        "baseline": {"run_id": baseline_id, "started": b_status.get("started", ""),
                     "client": b_status.get("client", ""),
                     "hosts": len(ports_b), "counts": find_count(findings_b)},
        "comparison": {"run_id": comparison_id, "started": c_status.get("started", ""),
                       "client": c_status.get("client", ""),
                       "hosts": len(ports_c), "counts": find_count(findings_c)},
        "new_hosts": new_hosts,
        "gone_hosts": gone_hosts,
        "host_rows": host_rows,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "changed_findings": changed_findings,
    }


def other_runs(exclude_run_id):
    """Runs other than the given one, for the report page's compare picker."""
    return [r for r in list_scans() if r["run_id"] != exclude_run_id][:30]


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
    sched_names = {s["id"]: s["name"] for s in load_schedules() if s.get("id")}
    for d in sorted(OUTPUT_ROOT.glob("scan-*"), reverse=True):
        if not d.is_dir():
            continue
        run_id = d.name.replace("scan-", "", 1)
        if not RUN_ID_RE.match(run_id):
            continue
        st = read_status(d)
        # Grouped count, same as the progress tile and the report -- see the
        # note in scan_progress() for why a raw line count disagrees with them.
        n_find = len(parse_findings(d))
        sched_id = st.get("_schedule", "")
        rows.append({
            "run_id": run_id,
            "state": st.get("state", "done"),
            "client": st.get("client", ""),
            "started": st.get("started", ""),
            "findings": n_find,
            "schedule": sched_names.get(sched_id, "") if sched_id else "",
        })
    return rows[:40]


# -------------------------------------------------------------- scheduling

_sched_lock = threading.Lock()
# When a scheduled run comes due while another scan is still running:
#   "asap"  -> run it as soon as the current scan finishes (retry shortly)
#   "skip"  -> drop this occurrence, run the next scheduled one
SCHEDULE_OVERLAPS = ["asap", "skip"]
SCHEDULER_RETRY_SECONDS = 30   # asap retry while another scan is running


def load_schedules():
    if not SCHEDULE_FILE.exists():
        return []
    try:
        data = json.loads(SCHEDULE_FILE.read_text())
    except (ValueError, OSError):
        return []
    return data if isinstance(data, list) else []


def save_schedules(schedules):
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCHEDULE_FILE.write_text(json.dumps(schedules, indent=2))


def parse_hhmm(value):
    m = re.match(r"^([01]?\d|2[0-3]):([0-5]\d)$", (value or "").strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def next_occurrence(sch, reference=None):
    """The next wall-clock moment this schedule should fire, in UTC."""
    reference = reference or utcnow()
    kind = sch.get("kind", "daily")
    if kind == "interval":
        try:
            hours = float(sch.get("interval_hours") or 24)
        except (TypeError, ValueError):
            hours = 24.0
        return reference + timedelta(hours=hours)

    hm = parse_hhmm(sch.get("time"))
    if hm is None:
        return reference + timedelta(days=1)
    hour, minute = hm
    candidate = reference.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if kind == "weekly":
        target = WEEKDAYS.index(sch.get("weekday", "mon"))
        delta = (target - candidate.weekday()) % 7
        if delta == 0 and candidate <= reference:
            delta = 7
        candidate += timedelta(days=delta)
    elif candidate <= reference:
        candidate += timedelta(days=1)
    return candidate


def ensure_next_run(sch, reference=None):
    if sch.get("next_run"):
        try:
            datetime.fromisoformat(sch["next_run"].replace("Z", "+00:00"))
            return
        except (ValueError, AttributeError):
            pass
    sch["next_run"] = next_occurrence(sch, reference).isoformat()


def make_schedule(name, targets, client, kind, time_s, weekday, interval,
                  profile="standard", overlap="asap", enabled=True,
                  avoid_fragile=True):
    """Validate schedule settings and return (schedule, error). Either a
    schedule dict with a next_run, or None and a message for the UI. Shared by
    the scan form's "repeat" checkbox and the standalone schedule form."""
    if not name:
        return None, "Give the schedule a name."
    if isinstance(targets, str):
        raw_targets = targets
        cleaned = clean_targets(targets)
    else:                        # already-cleaned list from the scan form
        cleaned = list(targets)
        raw_targets = "\n".join(cleaned)
    if not cleaned:
        return None, "Enter target networks for the schedule."
    if kind not in SCHEDULE_KINDS:
        return None, "Unknown schedule type."
    if kind in ("daily", "weekly") and parse_hhmm(time_s) is None:
        return None, "Enter the run time as HH:MM (24-hour, UTC)."
    if kind == "weekly" and weekday not in WEEKDAYS:
        return None, "Pick a valid weekday."
    if kind == "interval":
        try:
            if float(interval) <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return None, "Interval must be a number of hours."
    if overlap not in SCHEDULE_OVERLAPS:
        return None, "Pick how overlapping runs are handled."
    sch = {
        "id": secrets.token_hex(6),
        "name": name,
        "targets": raw_targets,
        "client": client,
        "kind": kind,
        "time": time_s if kind != "interval" else "",
        "weekday": weekday if kind == "weekly" else "mon",
        "interval_hours": interval if kind == "interval" else "",
        "profile": profile,
        "enabled": enabled,
        "overlap": overlap,
        "avoid_fragile": avoid_fragile,
        "created": utcnow().isoformat(),
        "last_run": None, "last_run_id": None, "note": None,
        "next_run": None,
    }
    ensure_next_run(sch)
    return sch, None


def parse_next_run(sch):
    try:
        return datetime.fromisoformat(sch.get("next_run", "").replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def list_schedules():
    """Schedules with display fields resolved (labels, human next-run)."""
    out = []
    for sch in load_schedules():
        ensure_next_run(sch)
        display = {
            "id": sch.get("id", ""),
            "name": sch.get("name", ""),
            "client": sch.get("client", ""),
            "profile": sch.get("profile", "standard"),
            "enabled": sch.get("enabled", True),
            "kind": sch.get("kind", "daily"),
            "overlap": sch.get("overlap", "asap"),
            "note": sch.get("note"),
            "last_run_id": sch.get("last_run_id"),
            "last_run": sch.get("last_run", ""),
        }
        if sch["kind"] == "interval":
            display["schedule_text"] = "every {0:g} hour{1}".format(
                float(sch.get("interval_hours") or 24),
                "s" if float(sch.get("interval_hours") or 24) != 1 else "")
        elif sch["kind"] == "weekly":
            display["schedule_text"] = WEEKDAY_LABEL.get(sch.get("weekday"), "") + \
                " at " + (sch.get("time") or "--:--")
        else:
            display["schedule_text"] = "daily at " + (sch.get("time") or "--:--")
        next_dt = parse_next_run(sch)
        display["next_run"] = next_dt.isoformat()[:16].replace("T", " ") if next_dt else ""
        out.append(display)
    return out


def tick_schedules():
    """One pass of the scheduler. Runs every few seconds from its own thread."""
    with _sched_lock:
        scheds = load_schedules()
        if not scheds:
            return
        save_schedules(scheds)          # persists any ensure_next_run backfill

    now = utcnow()
    dirty = False
    for sch in scheds:
        if not sch.get("enabled", True):
            continue
        due = parse_next_run(sch)
        if due is None:
            ensure_next_run(sch, now)
            dirty = True
            continue
        if due > now:
            continue

        targets = clean_targets(sch.get("targets", ""))
        if not targets:
            sch["note"] = "Skipped: no valid targets remain."
            sch["next_run"] = next_occurrence(sch, now).isoformat()
            dirty = True
            continue

        with JOBS_LOCK:
            running = any(p.poll() is None for p in JOBS.values())
        if running:
            due_text = due.isoformat()[:16].replace("T", " ")
            if sch.get("overlap", "asap") == "skip":
                # Drop this occurrence; the next scheduled one still fires.
                sch["note"] = (f"Skipped: another scan was running at {due_text} UTC. "
                               "Next scheduled run still fires.")
                sch["next_run"] = next_occurrence(sch, now).isoformat()
            else:
                # asap: keep it pending and retry shortly, so it launches
                # within seconds of the running scan finishing.
                sch["note"] = (f"Another scan was running at {due_text} UTC; "
                               "will run when it finishes.")
                sch["next_run"] = (now + timedelta(seconds=SCHEDULER_RETRY_SECONDS)).isoformat()
            dirty = True
            continue

        try:
            opts = profile_opts(sch.get("profile", "standard"))
            opts["_client"] = (sch.get("client") or "").strip()
            opts["_schedule"] = sch.get("id", "")
            opts["AVOID_FRAGILE_ICS"] = "true" if sch.get("avoid_fragile", True) else "false"
            run_id = start_scan(targets, opts)
            sch["last_run"] = now.isoformat()
            sch["last_run_id"] = run_id
            sch["note"] = None
        except Exception as exc:        # keep the loop alive; never crash the web UI
            sch["note"] = f"Could not launch the scan: {exc}"
        sch["next_run"] = next_occurrence(sch, now).isoformat()
        dirty = True

    if dirty:
        with _sched_lock:
            save_schedules(scheds)


def scheduler_loop():
    while True:
        try:
            tick_schedules()
        except Exception:
            pass
        time.sleep(20)


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
            "sev_meaning": SEVERITY_MEANING,
            "host_subnets": [x.strip() for x in HOST_SUBNETS.split(",") if x.strip()],
            "template_count": template_count(),
            "tpl_message": _tpl_update["message"],
            "build_ref": BUILD_REF, "build_date": BUILD_DATE}


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
    return render_index()


def render_index(error=None, prefill=None, status=200):
    """Render the scans page. `prefill` repopulates the form after a validation
    error or a rescan link so the operator does not retype everything."""
    ctx = {"scans": list_scans(),
           "schedules": list_schedules(),
           "sched_kinds": SCHEDULE_KINDS,
           "weekdays": WEEKDAYS,
           "flash": session.pop("flash", None),
           "error": error,
           "prefill_avoid_fragile": True}
    ctx.update(prefill or {})
    return render_template("index.html", **ctx), status


@app.route("/rescan/<run_id>")
def rescan(run_id):
    """Prefill the new-scan form from a past run's scope, client, and profile.

    Does not launch anything -- the operator still reviews what is filled in
    and ticks authorisation themselves, same as starting from scratch.
    """
    run_dir = run_dir_for(run_id)
    status = read_status(run_dir)
    tf = run_dir / "targets.input"
    if not tf.exists():
        tf = run_dir / "targets.txt"
    targets = tf.read_text(errors="replace").strip() if tf.exists() else ""
    return render_index(prefill={"prefill_targets": targets,
                                 "prefill_client": status.get("client", ""),
                                 "prefill_profile": status.get("profile", "standard"),
                                 "prefill_avoid_fragile": status.get("avoid_fragile_ics", "true") == "true"})


@app.route("/scan", methods=["POST"])
def scan():
    # The checkbox is required in the form, but a form can be posted directly.
    if not request.form.get("authorized"):
        return render_index(error="Confirm you have written authorization before starting a scan.",
                            prefill=form_prefill(request.form), status=400)

    targets = clean_targets(request.form.get("targets", ""))
    if not targets:
        return render_index(error="Enter at least one target address or range.",
                            prefill=form_prefill(request.form), status=400)

    profile = request.form.get("profile", "standard")
    client = request.form.get("client", "").strip()
    # Unchecked checkboxes are simply absent from form data; the field
    # defaults to checked in the template, so absence here only happens if
    # the operator deliberately unticked it.
    avoid_fragile = request.form.get("avoid_fragile") == "on"

    # Scheduling a repeat: create a schedule instead of launching right now.
    # The first run happens at the next occurrence, so the operator sees the
    # confirmation in the "Scheduled scans" list rather than a scan page.
    if request.form.get("schedule"):
        name = (request.form.get("sched_name") or client or targets[0]).strip()
        sch, err = make_schedule(
            name, targets, client,
            request.form.get("sched_kind", "daily"),
            request.form.get("sched_time", ""),
            request.form.get("sched_weekday", "mon").strip().lower(),
            request.form.get("sched_interval_hours", "24"),
            profile,
            request.form.get("overlap", "asap"),
            avoid_fragile=avoid_fragile)
        if err:
            return render_index(error=err, prefill=form_prefill(request.form), status=400)
        with _sched_lock:
            scheds = load_schedules()
            scheds.append(sch)
            save_schedules(scheds)
        session["flash"] = f"Scheduled “{sch['name']}”. First run at the next occurrence."
        return redirect(url_for("index"))

    opts = {"_client": client, "_profile": profile,
            "AVOID_FRAGILE_ICS": "true" if avoid_fragile else "false"}
    opts.update(profile_opts(profile))

    run_id = start_scan(targets, opts)
    return redirect(url_for("scan_view", run_id=run_id))


def form_prefill(form):
    """Copy submitted form values into the render prefill namespace."""
    return {
        "prefill_targets": form.get("targets", ""),
        "prefill_client": form.get("client", ""),
        "prefill_profile": form.get("profile", "standard"),
        "prefill_avoid_fragile": form.get("avoid_fragile") == "on",
        "prefill_schedule": form.get("schedule") == "on",
        "prefill_sched_name": form.get("sched_name", ""),
        "prefill_sched_kind": form.get("sched_kind", "daily"),
        "prefill_sched_time": form.get("sched_time", ""),
        "prefill_sched_weekday": form.get("sched_weekday", "mon"),
        "prefill_sched_interval": form.get("sched_interval_hours", "24"),
        "prefill_overlap": form.get("overlap", "asap"),
    }


_templates = {"count": 0, "checked": 0.0}
_tpl_update = {"running": False, "message": ""}


def template_count():
    """Cached: walking ~13k files on every page load would be wasteful."""
    import time
    if time.time() - _templates["checked"] > 300:
        try:
            _templates["count"] = sum(1 for _ in TEMPLATE_DIR.rglob("*.yaml"))
        except OSError:
            _templates["count"] = 0
        _templates["checked"] = time.time()
    return _templates["count"]


@app.route("/templates/update", methods=["POST"])
def templates_update():
    if not _tpl_update["running"]:
        _tpl_update.update(running=True, message="Updating templates...")

        def run():
            try:
                r = subprocess.run(["nuclei", "-update-templates", "-silent"],
                                   capture_output=True, text=True, timeout=600)
                ok = r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
            _tpl_update.update(
                running=False,
                message="Templates updated." if ok else
                        "Could not update templates. This appliance may have no internet access.")
            _templates["checked"] = 0.0

        threading.Thread(target=run, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/schedules", methods=["POST"])
def schedule_create():
    name = request.form.get("name", "").strip()
    targets = request.form.get("targets", "").strip()
    kind = request.form.get("kind", "daily")
    time_s = request.form.get("time", "").strip()
    weekday = request.form.get("weekday", "mon").strip().lower()
    interval = request.form.get("interval_hours", "24").strip()
    profile = request.form.get("profile", "standard")
    client = request.form.get("client", "").strip()
    enabled = request.form.get("enabled") == "on"
    overlap = request.form.get("overlap", "asap")

    sch, err = make_schedule(name, targets, client, kind, time_s, weekday,
                             interval, profile, overlap, enabled)
    if err:
        session["flash"] = err
        return redirect(url_for("index"))

    with _sched_lock:
        scheds = load_schedules()
        scheds.append(sch)
        save_schedules(scheds)
    session["flash"] = f"Scheduled “{name}”."
    return redirect(url_for("index"))


@app.route("/schedules/<sid>/toggle", methods=["POST"])
def schedule_toggle(sid):
    with _sched_lock:
        scheds = load_schedules()
        for sch in scheds:
            if sch.get("id") == sid:
                sch["enabled"] = not sch.get("enabled", True)
                if sch["enabled"]:
                    ensure_next_run(sch)
                save_schedules(scheds)
                break
    return redirect(url_for("index"))


@app.route("/schedules/<sid>/delete", methods=["POST"])
def schedule_delete(sid):
    with _sched_lock:
        scheds = load_schedules()
        scheds = [s for s in scheds if s.get("id") != sid]
        save_schedules(scheds)
    return redirect(url_for("index"))


@app.route("/schedules/<sid>/run", methods=["POST"])
def schedule_run_now(sid):
    """Launch a scheduled scan immediately, outside its schedule."""
    sch = next((s for s in load_schedules() if s.get("id") == sid), None)
    if sch is None:
        session["flash"] = "That schedule no longer exists."
        return redirect(url_for("index"))
    targets = clean_targets(sch.get("targets", ""))
    if not targets:
        session["flash"] = "The schedule has no valid targets."
        return redirect(url_for("index"))
    opts = profile_opts(sch.get("profile", "standard"))
    opts["_client"] = (sch.get("client") or "").strip()
    opts["_schedule"] = sid
    opts["AVOID_FRAGILE_ICS"] = "true" if sch.get("avoid_fragile", True) else "false"
    run_id = start_scan(targets, opts)
    with _sched_lock:
        scheds = load_schedules()
        for s in scheds:
            if s.get("id") == sid:
                s["last_run"] = utcnow().isoformat()
                s["last_run_id"] = run_id
                s["note"] = None
        save_schedules(scheds)
    return redirect(url_for("scan_view", run_id=run_id))


@app.route("/api/update-check")
def update_check():
    """Report whether the repository has moved on. Never updates anything.

    Rebuilding from the web UI would mean giving this container control of the
    Docker daemon, which is root on the appliance. Not worth it for the
    convenience, so this only tells you a newer version exists.
    """
    if not BUILD_REF or not UPDATE_CHECK_URL:
        return jsonify({"known": False, "reason": "No version information for this build."})
    req = urllib.request.Request(
        UPDATE_CHECK_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "nd-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            latest = json.loads(r.read().decode())["sha"][:len(BUILD_REF)]
    except urllib.error.HTTPError as e:
        # Distinguish these: "no internet" is wrong and misleading when the
        # request arrived fine and GitHub simply declined to answer it.
        if e.code == 404:
            reason = ("This appliance was installed from a private repository, "
                      "which the update check cannot read without credentials. "
                      "Set UPDATE_CHECK_URL to a public repository to enable it.")
        elif e.code in (403, 429):
            reason = "GitHub is rate-limiting this appliance. Try again later."
        else:
            reason = f"GitHub returned HTTP {e.code}."
        return jsonify({"known": False, "reason": reason})
    except urllib.error.URLError as e:
        return jsonify({"known": False,
                        "reason": f"Could not reach GitHub ({e.reason}). No internet access?"})
    except (ValueError, KeyError, TimeoutError, OSError):
        return jsonify({"known": False, "reason": "GitHub returned an unexpected response."})
    return jsonify({"known": True, "current": BUILD_REF, "latest": latest,
                    "update_available": latest != BUILD_REF})


@app.route("/scan/<run_id>/stop", methods=["POST"])
def stop_scan(run_id):
    run_dir = run_dir_for(run_id)
    with JOBS_LOCK:
        proc = JOBS.get(run_id)

    if read_status(run_dir).get("state") == "running":
        write_status(run_dir, state="cancelled", finished=utcnow().isoformat(),
                     note="Stopped from the web interface.")

    if proc is not None:
        # Signal the whole process group: scan.sh's children do the actual work
        # and outlive it if signaled individually.
        try:
            pgid = os.getpgid(proc.pid)
        except OSError:
            pgid = None

        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except OSError:
                pass

            def reaper():
                # Always escalate. scan.sh exits almost immediately once
                # signaled, but naabu or nmap can keep running and keep
                # putting traffic on the client's network, so waiting only on
                # the parent is not enough.
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    pass
                time.sleep(2)
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except OSError:
                    pass

            threading.Thread(target=reaper, daemon=True).start()

    return redirect(url_for("scan_view", run_id=run_id))


@app.route("/purge", methods=["POST"])
def purge():
    """Delete stored results. Running scans are left alone."""
    removed = skipped = 0
    for d in sorted(OUTPUT_ROOT.glob("scan-*")):
        if not d.is_dir():
            continue
        if read_status(d).get("state") == "running":
            skipped += 1
            continue
        shutil.rmtree(d, ignore_errors=True)
        removed += 1
    session["flash"] = (f"Deleted {removed} scan result(s)."
                        + (f" {skipped} still running and left in place." if skipped else ""))
    return redirect(url_for("index"))


def render_standalone_report(run_id):
    """A report render with the stylesheet inlined.

    The normal page links /static/style.css, which stops resolving the
    moment the file is out of the appliance's hands -- archived, emailed,
    opened on a laptop with no route back here. This makes each export a
    single file that looks right on its own.
    """
    html = render_template("report.html", r=build_report(run_id))
    css = (Path(app.static_folder) / "style.css").read_text()
    return html.replace(
        '<link rel="stylesheet" href="/static/style.css">',
        f"<style>\n{css}\n</style>")


def selected_run_ids():
    """Validated run_ids from a bulk form post -- never trust the raw list."""
    out = []
    for rid in request.form.getlist("run_ids"):
        if RUN_ID_RE.match(rid) and (OUTPUT_ROOT / f"scan-{rid}").is_dir():
            out.append(rid)
    return out


@app.route("/reports/export", methods=["POST"])
def reports_export():
    run_ids = selected_run_ids()
    if not run_ids:
        session["flash"] = "No reports selected."
        return redirect(url_for("index"))

    fmt = request.form.get("fmt", "html")
    if fmt not in EXPORT_FORMATS:
        fmt = "html"

    buf = export_archive(run_ids, fmt)
    ts = utcnow().strftime("%Y%m%d-%H%M%S")
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"reports-{fmt}-{ts}.zip")


@app.route("/report/<run_id>/export/<fmt>")
def report_export(run_id, fmt):
    """A single run in one format, for one-off downloads from the report page.

    CSV is two files (inventory + findings) so it downloads as a small zip,
    matching what the bulk export produces.
    """
    if fmt not in EXPORT_FORMATS:
        abort(404)
    run_dir = run_dir_for(run_id)       # 404 for unknown run
    client = (read_status(run_dir).get("client") or "report").strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", client).strip("_") or "report"

    if fmt == "csv":
        buf = export_archive([run_id], "csv")
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"{safe}-{run_id}-csv.zip")

    data, mimetype = report_export_bytes(fmt, run_id)
    return send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=True,
                     download_name=f"{safe}-{run_id}.{fmt}")


@app.route("/reports/delete", methods=["POST"])
def reports_delete():
    run_ids = selected_run_ids()
    removed = skipped = 0
    for rid in run_ids:
        d = run_dir_for(rid)
        if read_status(d).get("state") == "running":
            skipped += 1
            continue
        shutil.rmtree(d, ignore_errors=True)
        removed += 1
    session["flash"] = (f"Deleted {removed} scan result(s)."
                        + (f" {skipped} still running and left in place." if skipped else ""))
    return redirect(url_for("index"))


@app.route("/scan/<run_id>")
def scan_view(run_id):
    run_dir = run_dir_for(run_id)
    return render_template("scan.html", run_id=run_id, status=read_status(run_dir))


@app.route("/api/scan/<run_id>/findings")
def scan_findings(run_id):
    """Grouped findings for the live dropdown on the progress page.

    nuclei writes nuclei.jsonl as matches happen rather than only at the end,
    so parse_findings works the same mid-scan as it does for the finished
    report -- this is that exact function, just exposed before the run is over.
    """
    run_dir = run_dir_for(run_id)
    findings = parse_findings(run_dir)
    LIMIT = 60
    out = [{
        "name": f["name"],
        "severity": f["severity"],
        "severity_label": SEVERITY_LABEL[f["severity"]],
        "description": f["description"],
        "assets": f["assets"][:6],
        "asset_count": len(f["assets"]),
    } for f in findings[:LIMIT]]
    return jsonify({"total": len(findings), "findings": out,
                    "truncated": max(0, len(findings) - LIMIT)})


@app.route("/api/scan/<run_id>")
def api_scan(run_id):
    run_dir = run_dir_for(run_id)
    status = read_status(run_dir)
    stage, label = stage_from_log(run_dir)
    payload = {"state": status.get("state", "done"), "stage": stage,
               "label": label, "log": log_tail(run_dir),
               "started": status.get("started", ""),
               "exit_code": status.get("exit_code")}
    payload.update(scan_progress(run_dir))
    return jsonify(payload)


@app.route("/report/<run_id>")
def report(run_id):
    return render_template("report.html", r=build_report(run_id),
                           others=other_runs(run_id))


@app.route("/compare", methods=["POST"])
def compare():
    """Validate a two-run comparison and redirect to its page."""
    a, b = request.form.get("run_a", "").strip(), request.form.get("run_b", "").strip()
    for rid in (a, b):
        if not RUN_ID_RE.match(rid) or not (OUTPUT_ROOT / f"scan-{rid}").is_dir():
            session["flash"] = "Pick two existing scans to compare."
            return redirect(url_for("index"))
    if a == b:
        session["flash"] = "Pick two different scans to compare."
        return redirect(url_for("index"))
    return redirect(url_for("diff_view", baseline=a, comparison=b))


@app.route("/compare/<baseline>/<comparison>")
def diff_view(baseline, comparison):
    run_dir_for(baseline)
    run_dir_for(comparison)
    return render_template("diff.html", d=compare_runs(baseline, comparison))


if __name__ == "__main__":
    reap_orphaned_runs()

    # Recurring scans run from this thread; they are launched exactly like
    # manual ones (same start_scan), so stop/purge/reporting all just work.
    threading.Thread(target=scheduler_loop, daemon=True).start()

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
