"""Static analysis with Semgrep: the community rulesets for each language the app uses, plus this
suite's own rules in rules/semgrep (MCP servers, Android, Firebase functions, Flutter). Metrics off;
code is never uploaded."""
import re
import tempfile
from pathlib import Path

from ..core import Finding, ROOT_RULES, load_json, need, run

NAME = "sast"
CATEGORY = "Code (SAST)"

# Registry packs by the kind of app. Fetched from semgrep.dev (rules only; no code leaves the
# machine). Packs are occasionally retired from the registry; scan() drops any that 404 and retries
# rather than failing, so a missing pack is a warning, not an outage.
PACKS = {
    "python": ["p/python", "p/bandit"],
    "android": ["p/kotlin", "p/java"],
    "firebase-functions": ["p/typescript", "p/javascript", "p/nodejs"],
    "flutter": ["p/dart"],  # may 404; dropped automatically if so
    "web": ["p/javascript", "p/xss"],
    "mcp": [],
}
COMMON = ["p/security-audit", "p/secrets", "p/owasp-top-ten", "p/github-actions", "p/dockerfile"]
# Rules the dedicated analyzers in this suite own and cover more precisely (e.g. the `android`
# scanner excludes launcher activities, where this Semgrep rule flags every activity). Dropping
# them avoids a wall of duplicate, lower-quality findings.
DROP_RULES = {
    "exported_activity", "exported-activity", "exported_service", "exported-service",
    "exported_broadcast_receiver", "exported-broadcast-receiver", "exported-content-provider",
    "android-manifest-cleartext-traffic", "android-allow-backup", "android-debuggable",
}
EXCLUDE = ["build", "node_modules", ".gradle", ".dart_tool", "dist", "Pods", "*.min.js", "test", "tests",
           "e2e", "*_test.dart", "*.test.ts", "*.test.js", "androidTest"]


def scan(app):
    need("semgrep", "brew install semgrep")
    configs = list(COMMON)
    for kind in app.kinds:
        configs += PACKS.get(kind, [])
    configs.append(str(ROOT_RULES / "semgrep"))
    configs = list(dict.fromkeys(configs))
    excludes = []
    for e in EXCLUDE + app.exclude:
        excludes += ["--exclude", e]
    dropped = []
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "semgrep.json"
        data = {}
        for _ in range(5):  # retry, dropping any pack the registry 404s, so one bad pack never sinks the scan
            cmd = ["semgrep", "scan", "--metrics=off", "--quiet", "--json", "--timeout", "30",
                   "--max-target-bytes", "2000000", "--jobs", "4"]
            for c in configs:
                cmd += ["--config", c]
            cmd += excludes + ["--output", str(out_file), str(app.path)]
            run(cmd, timeout=3600, ok_codes=(0, 1, 7))
            data = load_json(out_file) or {}
            bad = []
            for err in data.get("errors", []):
                m = re.search(r"from (https://semgrep\.dev/\S+?) HTTP (?:404|40\d)", err.get("message", ""))
                if m:
                    pack = "p/" + m.group(1).rstrip("/").split("/p/")[-1] if "/p/" in m.group(1) else None
                    bad += [c for c in configs if pack and c == pack]
            bad = [c for c in bad if c not in dropped]
            if not bad:
                break
            dropped += bad
            configs = [c for c in configs if c not in bad]
    findings = []
    if dropped:
        findings.append(Finding(NAME, "pack-unavailable", "info",
                                "Semgrep pack(s) unavailable, skipped: " + ", ".join(dropped), category=CATEGORY,
                                detail="The registry returned 404 for these packs; the rest of the scan ran."))
    for r in data.get("results", []):
        rule_id = r.get("check_id", "").split(".")[-1]
        if rule_id in DROP_RULES:
            continue
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        sev = meta.get("appsec_severity") or {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            extra.get("severity", ""), "medium")
        # Registry rules mark how sure they are; low-confidence audit rules drop a step.
        if str(meta.get("confidence", "")).upper() == "LOW" and sev in ("high", "medium"):
            sev = {"high": "medium", "medium": "low"}[sev]
        path = r.get("path", "")
        if path.startswith(str(app.path)):
            path = path[len(str(app.path)):].lstrip("/")
        refs = meta.get("references") or []
        cwe = meta.get("cwe") or []
        findings.append(Finding(
            NAME, r.get("check_id", "").split(".")[-1], sev, extra.get("message", "").split("\n")[0][:200],
            path, r.get("start", {}).get("line", 0), category=meta.get("appsec_category", CATEGORY),
            detail=extra.get("message", "") + ("\n" + ", ".join(cwe) if cwe else ""),
            fix=meta.get("fix_hint", extra.get("fix", "")) or "",
            references=refs if isinstance(refs, list) else [refs]))
    errors = [e for e in data.get("errors", []) if e.get("level") == "error"]
    if errors and not findings and not data.get("results"):
        raise RuntimeError("semgrep: " + errors[0].get("message", "failed")[:500])
    return findings
