"""The orchestrator: load the apps, run each scanner that applies, apply suppressions, and write
the reports. A scanner is a module in suite/scanners with a scan(app) -> list[Finding] function and
a NAME. Scanners that raise Skip are recorded as skipped, not as failures."""
import argparse
import datetime
import importlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

from .core import App, RANK, Skip, worst
from . import report

ROOT = Path(__file__).resolve().parents[1]

# Order is report order. Each applies to the kinds listed, or all kinds when the set is empty.
SCANNERS = [
    ("secrets", set()),
    ("repo_hygiene", set()),
    ("sca", set()),
    ("sast", set()),
    ("iac", set()),
    ("firebase_rules", {"firebase", "android", "flutter", "python", "web", "firebase-functions"}),
    ("firebase_config", {"firebase", "firebase-functions", "web"}),
    ("android", {"android", "flutter"}),
    ("llm_static", set()),
]


def load_apps(config_path, only=None):
    spec = json.loads(Path(config_path).read_text())
    base = Path(config_path).resolve().parent.parent
    apps = []
    for name, s in spec["apps"].items():
        if only and name not in only:
            continue
        apps.append(App(name, s, base))
    return apps


def load_suppressions(path):
    if not path or not Path(path).exists():
        return []
    return json.loads(Path(path).read_text()).get("suppress", [])


def apply_suppressions(findings, rules):
    for f in findings:
        for r in rules:
            if r.get("fingerprint") == f.fingerprint or (
                    r.get("scanner", f.scanner) == f.scanner and r.get("rule") in (None, f.rule)
                    and (r.get("file") in (None, f.file)) and (r.get("app") in (None, f.app))):
                f.suppressed = r.get("reason", "suppressed")
                break
    return findings


def scan_app(app, scanners, suppressions, verbose=False):
    result = {"app": app.name, "repo": app.repo, "path": str(app.path), "kinds": app.kinds,
              "findings": [], "skipped": [], "errored": []}
    for mod_name, kinds in scanners:
        module = importlib.import_module("suite.scanners." + mod_name)
        name = getattr(module, "NAME", mod_name)
        if kinds and not (set(app.kinds) & kinds):
            continue
        if not app.wants(name):
            continue
        start = time.time()
        if verbose:
            print("  [%s] %s ..." % (app.name, name), file=sys.stderr, flush=True)
        try:
            found = module.scan(app)
            for f in found:
                f.app = app.name
            apply_suppressions(found, suppressions)
            result["findings"] += [f.to_dict() for f in found]
            if verbose:
                live = sum(1 for f in found if not f.suppressed)
                print("    %d findings (%.1fs)" % (live, time.time() - start), file=sys.stderr, flush=True)
        except Skip as e:
            result["skipped"].append(name)
            if verbose:
                print("    skipped: %s" % e, file=sys.stderr, flush=True)
        except Exception as e:  # a broken scanner must not sink the whole run
            result["errored"].append({"scanner": name, "note": str(e)})
            if verbose:
                print("    ERROR: %s\n%s" % (e, traceback.format_exc()), file=sys.stderr, flush=True)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the security suite against the configured apps.")
    ap.add_argument("--config", default=str(ROOT / "config" / "apps.json"))
    ap.add_argument("--suppress", default=str(ROOT / "config" / "suppressions.json"))
    ap.add_argument("--app", action="append", help="only this app (repeatable)")
    ap.add_argument("--scanner", action="append", help="only this scanner (repeatable)")
    ap.add_argument("--out", default=str(ROOT / "reports"))
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info", "never"],
                    help="exit non-zero if any live finding is at least this severe (default high)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    scanners = [(m, k) for m, k in SCANNERS if not args.scanner or m in args.scanner
                or getattr(importlib.import_module("suite.scanners." + m), "NAME", m) in args.scanner]
    apps = load_apps(args.config, set(args.app) if args.app else None)
    suppressions = load_suppressions(args.suppress)
    if not apps:
        print("No apps matched.", file=sys.stderr)
        return 2

    run = {"generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
           "version": "1.0.0", "apps": []}
    for app in apps:
        if args.verbose:
            print("Scanning %s (%s)" % (app.name, app.path), file=sys.stderr, flush=True)
        if not app.path.exists():
            run["apps"].append({"app": app.name, "repo": app.repo, "path": str(app.path), "findings": [],
                                "skipped": [], "errored": [{"scanner": "-", "note": "path does not exist"}]})
            continue
        run["apps"].append(scan_app(app, scanners, suppressions, args.verbose))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report.write_json(run, out / "findings.json")
    report.write_sarif(run["apps"], out / "findings.sarif")
    report.write_markdown(run, out / "report.md")
    print("Reports written to %s" % out, file=sys.stderr)

    worst_rank = RANK[args.fail_on] if args.fail_on != "never" else -1
    live = [RANK[f["severity"]] for app in run["apps"] for f in app["findings"] if not f.get("suppressed")]
    top = min(live) if live else 99
    return 1 if args.fail_on != "never" and top <= worst_rank else 0


if __name__ == "__main__":
    sys.exit(main())
