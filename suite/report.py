"""Turn findings into a JSON file, a SARIF file, and a readable Markdown report."""
import datetime
import json
from pathlib import Path

from .core import RANK, SEVERITIES

BADGE = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _counts(findings):
    """findings are serialized dicts."""
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        if not f.get("suppressed"):
            c[f["severity"]] += 1
    return c


def write_json(run, out):
    out.write_text(json.dumps(run, indent=2, default=str))


def _sarif_level(sev):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[sev]


def write_sarif(apps, out):
    runs = []
    for app in apps:
        rules, results = {}, []
        for f in app["findings"]:
            rid = "%s/%s" % (f["scanner"], f["rule"])
            rules.setdefault(rid, {"id": rid, "name": f["rule"],
                                   "shortDescription": {"text": f["title"][:120]},
                                   "defaultConfiguration": {"level": _sarif_level(f["severity"])},
                                   "properties": {"category": f.get("category", ""), "security-severity":
                                                  {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "3.0",
                                                   "info": "1.0"}[f["severity"]]}})
            res = {"ruleId": rid, "level": _sarif_level(f["severity"]),
                   "message": {"text": f["title"] + ("\n\n" + f["detail"] if f["detail"] else "")},
                   "partialFingerprints": {"appsec/v1": f["fingerprint"]}}
            if f.get("file"):
                res["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, f.get("line", 0) or 1)}}}]
            if f.get("suppressed"):
                res["suppressions"] = [{"kind": "inSource", "justification": f["suppressed"]}]
            results.append(res)
        runs.append({"tool": {"driver": {"name": "Flawhound", "informationUri":
                     "https://github.com/deepankar17", "rules": list(rules.values())}},
                     "results": results,
                     "properties": {"app": app["app"]}})
    out.write_text(json.dumps({"version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}, indent=2))


def _fmt_finding(f):
    head = "- %s **%s** — %s" % (BADGE[f["severity"]], f["severity"].upper(), f["title"])
    lines = [head]
    if f.get("file"):
        loc = f["file"] + (":%d" % f["line"] if f.get("line") else "")
        lines.append("  - `%s`" % loc)
    if f.get("detail"):
        lines.append("  - %s" % f["detail"].replace("\n", " ").strip()[:400])
    if f.get("fix"):
        lines.append("  - _Fix:_ %s" % f["fix"][:400])
    if f.get("references"):
        lines.append("  - " + " ".join(f["references"][:2]))
    if f.get("suppressed"):
        lines.append("  - _Suppressed: %s_" % f["suppressed"])
    return "\n".join(lines)


def write_markdown(run, out):
    L = []
    L.append("# Security review\n")
    L.append("_%s · Flawhound_\n" % run["generated"])
    total = _counts([_dict(f) for app in run["apps"] for f in app["findings"]])
    L.append("## Summary\n")
    L.append("| App | " + " | ".join("%s %s" % (BADGE[s], s.title()) for s in SEVERITIES) + " |")
    L.append("|" + "---|" * (len(SEVERITIES) + 1))
    for app in run["apps"]:
        c = _counts([_dict(f) for f in app["findings"]])
        L.append("| **%s** | " % app["app"] + " | ".join(str(c[s]) for s in SEVERITIES) + " |")
    L.append("| **All** | " + " | ".join(str(total[s]) for s in SEVERITIES) + " |\n")
    skipped = {s for app in run["apps"] for s in app.get("skipped", [])}
    if skipped:
        L.append("> Scanners skipped somewhere (tool missing or not applicable): %s\n" % ", ".join(sorted(skipped)))
    for app in run["apps"]:
        L.append("\n## %s\n" % app["app"])
        if app.get("repo"):
            L.append("`%s`\n" % app["repo"])
        findings = sorted([_dict(f) for f in app["findings"]],
                          key=lambda f: (RANK[f["severity"]], f["category"], f["scanner"]))
        live = [f for f in findings if not f["suppressed"]]
        if not live:
            L.append("_No findings._\n")
        by_cat = {}
        for f in live:
            by_cat.setdefault(f["category"] or f["scanner"], []).append(f)
        for cat in sorted(by_cat, key=lambda c: RANK[min((x["severity"] for x in by_cat[c]), key=RANK.get)]):
            L.append("\n### %s\n" % cat)
            for f in by_cat[cat]:
                L.append(_fmt_finding(f))
        suppressed = [f for f in findings if f["suppressed"]]
        if suppressed:
            L.append("\n<details><summary>%d suppressed</summary>\n" % len(suppressed))
            for f in suppressed:
                L.append(_fmt_finding(f))
            L.append("\n</details>")
        for s in app.get("errored", []):
            L.append("\n> Scanner `%s` errored: %s" % (s["scanner"], s["note"][:300]))
    out.write_text("\n".join(L) + "\n")


def _dict(f):
    return f
