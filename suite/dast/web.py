"""Web DAST by orchestrating trusted scanners against a running site/endpoint.

- nuclei: template-based checks (misconfig, exposures, known CVEs, default creds). The default,
  non-destructive template set is used for any target; the fuller set is added only for an
  intrusive run against a non-prod target.
- OWASP ZAP (if available via `zap.sh` or Docker): baseline passive scan for a quick pass, or a
  full active scan (spider + attack) only for an authorized intrusive, non-prod target.

Both are established, widely-used tools; Argus just drives them, maps their output into the common
Finding shape, and enforces the authorization gate first.
"""
import json
import shutil
import tempfile
from pathlib import Path

from ..core import Finding
from .core import Target, authorize
from .shared import run_tool, tool_available

NAME = "web"
CATEGORY = "Web (DAST)"


def _nuclei(target: Target, intrusive: bool):
    if not tool_available("nuclei"):
        return [], "nuclei not installed (brew install nuclei)"
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "nuclei.jsonl"
        # -dast enables the active template set; omit it for a safe pass. Rate-limited, no interactsh
        # out to the public server for a prod run.
        cmd = ["nuclei", "-target", target.url, "-jsonl", "-o", str(out), "-silent", "-no-color",
               "-rate-limit", "30", "-severity", "info,low,medium,high,critical"]
        if intrusive:
            cmd += ["-dast"]
        else:
            cmd += ["-exclude-tags", "dos,fuzz,intrusive"]
        run_tool(cmd, timeout=1800, ok_codes=range(0, 256))
        if out.exists():
            for line in out.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                info = r.get("info", {})
                findings.append(Finding(
                    NAME, r.get("template-id", "nuclei"), info.get("severity", "info"),
                    "%s — %s" % (info.get("name", ""), target.host),
                    r.get("matched-at", target.url), 0, category=CATEGORY,
                    detail=info.get("description", "") or "", app=target.app,
                    references=(info.get("reference") or [])[:3] if isinstance(info.get("reference"), list) else []))
    return findings, ""


def _zap(target: Target, intrusive: bool):
    zap = shutil.which("zap.sh") or shutil.which("zap-baseline.py")
    docker = tool_available("docker") and _docker_up()
    if not zap and not docker:
        return [], "ZAP not available (install OWASP ZAP, or start Docker for the zaproxy image)"
    findings = []
    # The container's /zap/wrk must be a bind-mountable host dir. Docker Desktop and Colima only
    # share paths under $HOME by default, so put the work dir there, not in the system tempdir.
    work_base = Path.home() / ".argus" / "zapwork"
    work_base.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=str(work_base))
    try:
        report = Path(tmp) / "zap.json"
        script = "zap-full-scan.py" if intrusive else "zap-baseline.py"
        if docker:
            cmd = ["docker", "run", "--rm", "-v", "%s:/zap/wrk:rw" % tmp, "-t",
                   "ghcr.io/zaproxy/zaproxy:stable", script, "-t", target.url, "-J", "zap.json", "-I"]
        else:
            cmd = [shutil.which(script) or script, "-t", target.url, "-J", str(report), "-I"]
        run_tool(cmd, timeout=5400, ok_codes=range(0, 256))
        data = {}
        if report.exists():
            try:
                data = json.loads(report.read_text())
            except ValueError:
                data = {}
        risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
        for site in data.get("site", []):
            for a in site.get("alerts", []):
                inst = (a.get("instances") or [{}])[0]
                findings.append(Finding(
                    NAME, "zap-" + str(a.get("pluginid", "")), risk.get(str(a.get("riskcode", "0")), "info"),
                    "%s — %s" % (a.get("alert", ""), target.host), inst.get("uri", target.url), 0,
                    category=CATEGORY, detail=(a.get("desc", "") or "").strip()[:600],
                    fix=(a.get("solution", "") or "").strip()[:400], app=target.app,
                    references=[r for r in (a.get("reference", "") or "").split("\n") if r][:2]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return findings, ""


def _docker_up():
    import subprocess
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def scan(target: Target, intrusive: bool, allow_prod_active: bool = False):
    authorize(target, intrusive=intrusive, allow_prod_active=allow_prod_active)
    findings, notes = [], []
    for fn in (_nuclei, _zap):
        got, note = fn(target, intrusive)
        findings += got
        if note:
            notes.append(note)
    if notes:
        findings.append(Finding(NAME, "tool-missing", "info", "; ".join(notes), target.url, category=CATEGORY,
                                app=target.app))
    # nuclei fires some templates once per DNS record / matched line (RDAP, missing-headers, TLS
    # version), so collapse identical (rule + title) hits into one.
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
