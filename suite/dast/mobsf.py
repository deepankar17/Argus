"""Deep Android analysis with MobSF (Mobile Security Framework) in a local Docker container.

MobSF does a thorough static analysis of a built app (APK/AAB): manifest, permissions, exported
components, certificate and signing, native libs, secrets/trackers, insecure API usage, network
security config, and a CVSS-scored summary. It runs entirely locally (the container never uploads
the app). Argus starts the container, drives MobSF's REST API (via curl, which handles large
multipart uploads reliably) to upload and scan the artifact, then maps MobSF's own security summary
(`appsec`) into the common Finding shape.

Static-only analysis of a built artifact (no instrumented device), so it is safe; it is grouped
under DAST because it needs the built app and the container runtime rather than the source tree.
"""
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..core import Finding
from .core import Target, authorize
from .shared import run_tool, tool_available

NAME = "mobsf"
CATEGORY = "Android (MobSF)"
CONTAINER = "argus-mobsf"
IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
BASE = "http://127.0.0.1:8000"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEV = {"high": "high", "warning": "medium", "hotspot": "low", "info": "info", "secure": "info"}


def _docker_up():
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _running():
    out = subprocess.run(["docker", "ps", "--filter", "name=" + CONTAINER, "--format", "{{.Names}}"],
                         capture_output=True, text=True)
    return CONTAINER in out.stdout


def _start_container():
    if not _running():
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        run_tool(["docker", "run", "-d", "--name", CONTAINER, "-p", "8000:8000", IMAGE], timeout=180)


def _api_key():
    for _ in range(60):
        logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True)
        for line in (logs.stdout + logs.stderr).splitlines():
            if "REST API Key" in line:
                return ANSI.sub("", line).split(":", 1)[-1].strip()
        time.sleep(3)
    return None


def _wait_ready():
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE, timeout=5)
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(3)
    return False


def _curl(args, timeout=900):
    out = subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args, capture_output=True, text=True,
                         timeout=timeout + 30)
    try:
        return json.loads(out.stdout)
    except ValueError:
        raise RuntimeError("MobSF API returned non-JSON: %s" % (out.stdout or out.stderr)[:300])


def _scan_one(artifact, app, key):
    name = Path(artifact).name
    up = _curl(["-F", "file=@%s" % artifact, "-H", "Authorization: " + key, BASE + "/api/v1/upload"])
    sha = up.get("hash")
    if not sha:
        raise RuntimeError("upload returned no hash: %s" % up)
    _curl(["-X", "POST", "-H", "Authorization: " + key, "-F", "hash=" + sha, BASE + "/api/v1/scan"])
    with tempfile.TemporaryDirectory() as tmp:
        rep = Path(tmp) / "report.json"
        subprocess.run(["curl", "-s", "--max-time", "900", "-X", "POST", "-H", "Authorization: " + key,
                        "-F", "hash=" + sha, BASE + "/api/v1/report_json", "-o", str(rep)],
                       capture_output=True, timeout=960)
        report = json.loads(rep.read_text())
    findings = []
    appsec = report.get("appsec", {})
    seen = set()
    for bucket in ("high", "warning", "hotspot"):
        for item in appsec.get(bucket, []) or []:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).split("\n")[0].strip()
            key_t = (bucket, title[:80])
            if key_t in seen:
                continue
            seen.add(key_t)
            findings.append(Finding(
                NAME, item.get("section", bucket)[:40] or bucket, SEV[bucket],
                "%s (%s)" % (title[:110], name), name, 0, category=CATEGORY, app=app,
                detail=str(item.get("description", "")).strip()[:500]))
    score = appsec.get("security_score")
    trackers = appsec.get("trackers")
    findings.append(Finding(NAME, "mobsf-score", "info",
                            "MobSF security score for %s: %s/100%s" % (
                                name, score, (", %s tracker(s)" % trackers if trackers else "")),
                            name, 0, category=CATEGORY, app=app,
                            detail="Package %s, version %s." % (report.get("package_name", "?"),
                                                               appsec.get("version_name", "?"))))
    return findings


def scan(target: Target, intrusive: bool = False, allow_prod_active: bool = False):
    authorize(target, intrusive=False, allow_prod_active=allow_prod_active)
    if not tool_available("docker") or not _docker_up():
        return [Finding(NAME, "docker-missing", "info", "Docker not available for MobSF", category=CATEGORY,
                        app=target.app, fix="Start Docker/Colima, then re-run.")]
    if not tool_available("curl"):
        return [Finding(NAME, "curl-missing", "info", "curl is required for the MobSF upload", category=CATEGORY,
                        app=target.app)]
    artifacts = [os.path.expanduser(a) for a in target.options.get("artifacts", [])]
    artifacts = [a for a in artifacts if Path(a).exists()]
    if not artifacts:
        return [Finding(NAME, "no-artifact", "info", "No built APK/AAB found for %s" % target.app, category=CATEGORY,
                        app=target.app, fix="Build the app (assembleRelease / flutter build apk) and point the target at it.")]
    _start_container()
    if not _wait_ready():
        return [Finding(NAME, "mobsf-not-ready", "info", "MobSF container did not become ready", category=CATEGORY,
                        app=target.app)]
    key = _api_key()
    if not key:
        return [Finding(NAME, "mobsf-no-key", "info", "Could not read the MobSF API key", category=CATEGORY,
                        app=target.app)]
    findings = []
    for artifact in artifacts:
        try:
            findings += _scan_one(artifact, target.app, key)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as e:
            findings.append(Finding(NAME, "mobsf-error", "info", "MobSF could not scan %s" % Path(artifact).name,
                                    category=CATEGORY, app=target.app, detail=str(e)[:300]))
    return findings
