"""Known-vulnerable dependencies (SCA). osv-scanner reads every lockfile (npm, pub, pip, gradle
lockfiles). Android projects often have no Gradle lockfile, so the Gradle version catalog
(gradle/libs.versions.toml) is also read and its Maven packages checked against OSV.dev directly.
Only package names and versions are sent to OSV.dev, never code."""
import json
import re
import tempfile
import urllib.request
from pathlib import Path

from ..core import Finding, load_json, need, run, tracked_set

NAME = "sca"
CATEGORY = "Dependencies (SCA)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"


def _sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def _vuln_severity(vuln, group_max=None):
    if group_max:
        return _sev_from_score(group_max)
    db = (vuln.get("database_specific") or {}).get("severity")
    if db:
        return db
    return "medium"


def _fixed_versions(vuln, pkg_name):
    fixed = []
    for aff in vuln.get("affected", []):
        if (aff.get("package") or {}).get("name") != pkg_name:
            continue
        for rng in aff.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(fixed))


def _finding(pkg, vuln, source, severity):
    name, version, eco = pkg["name"], pkg.get("version", "?"), pkg.get("ecosystem", "")
    fixed = _fixed_versions(vuln, name)
    aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    vid = vuln.get("id", "")
    return Finding(
        NAME, vid, severity, "%s %s: %s" % (name, version, (vuln.get("summary") or vid)[:140]), source, 0,
        category=CATEGORY,
        detail="%s package %s %s is affected by %s%s." % (eco, name, version, vid,
                                                         (" (" + ", ".join(aliases) + ")") if aliases else ""),
        fix=("Upgrade to %s or later." % fixed[0]) if fixed else "No fixed version published yet; check the advisory.",
        references=["https://osv.dev/vulnerability/" + vid])


def _osv_scanner(app):
    need("osv-scanner", "brew install osv-scanner")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "osv.json"
        run(["osv-scanner", "scan", "source", "-r", "--format", "json", "--output-file", str(out),
             str(app.path)], timeout=1800, ok_codes=(0, 1, 128))
        data = load_json(out) or {}
    tracked = tracked_set(app.path)
    findings = []
    for res in data.get("results", []):
        source = (res.get("source") or {}).get("path", "")
        if source.startswith(str(app.path)):
            source = source[len(str(app.path)):].lstrip("/")
        if re.search(r"(^|/)(build|node_modules)/", source):
            continue
        # A lockfile git does not track is vendored tooling (NDK, SDKs) or a nested scratch worktree.
        if tracked is not None and source not in tracked:
            continue
        for p in res.get("packages", []):
            groups = {i: g.get("max_severity") for g in p.get("groups", []) for i in g.get("ids", [])}
            seen = set()
            for v in p.get("vulnerabilities", []):
                # One finding per advisory group (GHSA and CVE ids of one bug are grouped by osv-scanner).
                group = next((g for g in p.get("groups", []) if v["id"] in g.get("ids", [])), None)
                key = tuple(sorted(group["ids"])) if group else (v["id"],)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(p["package"], v, source, _vuln_severity(v, groups.get(v["id"]))))
    return findings


# ---- Gradle version catalog ----

def parse_catalog(text):
    """Maven coordinates (group, artifact, version) with an explicit version in a libs.versions.toml."""
    versions, libs, section = {}, [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[(\w[\w-]*)\]$", line)
        if m:
            section = m.group(1)
            continue
        m = re.match(r'^([\w.-]+)\s*=\s*(.+)$', line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if section == "versions":
            sm = re.match(r'^"([^"]+)"$', value)
            if sm:
                versions[key] = sm.group(1)
            else:  # { strictly = "x" } / { prefer = "x" }
                sm = re.search(r'(?:strictly|require|prefer)\s*=\s*"([^"]+)"', value)
                if sm:
                    versions[key] = sm.group(1)
        elif section == "libraries":
            if value.startswith('"'):
                parts = value.strip('"').split(":")
                if len(parts) == 3:
                    libs.append((parts[0], parts[1], parts[2]))
                continue

            def field(name):
                fm = re.search(r'(?<![\w.])' + re.escape(name) + r'\s*=\s*"([^"]+)"', value)
                return fm.group(1) if fm else None
            module = field("module")
            group, artifact = (module.split(":", 1) if module else (field("group"), field("name")))
            version = field("version")
            if not version:
                ref = field("version.ref")
                version = versions.get(ref) if ref else None
            if group and artifact and version:
                libs.append((group, artifact, version))
    return libs


def _post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def _get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def _catalogs(app):
    findings = []
    for cat in app.path.rglob("libs.versions.toml"):
        if re.search(r"/(build|node_modules|\.gradle|\.claude|worktrees|\.git)/", str(cat)):
            continue
        libs = parse_catalog(cat.read_text(errors="replace"))
        if not libs:
            continue
        source = str(cat.relative_to(app.path))
        queries = [{"package": {"name": "%s:%s" % (g, a), "ecosystem": "Maven"}, "version": v} for g, a, v in libs]
        results = []
        for i in range(0, len(queries), 500):
            results += _post(OSV_BATCH, {"queries": queries[i:i + 500]}).get("results", [])
        for q, res in zip(queries, results):
            for v in res.get("vulns", []) or []:
                full = _get(OSV_VULN + v["id"])
                sev = (full.get("database_specific") or {}).get("severity") or "medium"
                pkg = {"name": q["package"]["name"], "version": q["version"], "ecosystem": "Maven"}
                findings.append(_finding(pkg, full, source, sev))
    return findings


def scan(app):
    findings = _osv_scanner(app)
    if "android" in app.kinds:
        try:
            findings += _catalogs(app)
        except OSError as e:  # offline: osv-scanner results still stand
            findings.append(Finding(NAME, "catalog-offline", "info", "Could not reach OSV.dev for the Gradle catalog",
                                    detail=str(e), category=CATEGORY))
    seen, unique = set(), []
    for f in findings:
        if (f.rule, f.title) not in seen:
            seen.add((f.rule, f.title))
            unique.append(f)
    return unique
