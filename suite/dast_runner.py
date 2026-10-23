"""Runner for the dynamic (DAST) scanners. Separate from the static `./argus` because these touch
running services. It reads config/dast.json, runs the scanner each target asks for, enforces the
authorization gate, and writes reports alongside the static ones (dast-report.md / dast-findings.*).

Targets that are not authorized, or intrusive runs against prod without --allow-prod-active, are
skipped with a clear note rather than run.
"""
import argparse
import datetime
import importlib
import json
import sys
import time
import traceback
from pathlib import Path

from .core import RANK
from .dast.core import NotAuthorized, Target
from . import report

ROOT = Path(__file__).resolve().parents[1]
SCANNERS = {
    "web": "suite.dast.web",
    "tls": "suite.dast.tls",
    "http-api": "suite.dast.http_api",
    "mcp": "suite.dast.mcp_dynamic",
    "firebase-emulator": "suite.dast.firebase_rules_dynamic",
}


def load_targets(path):
    spec = json.loads(Path(path).read_text()) if Path(path).exists() else {"targets": []}
    out = []
    for t in spec.get("targets", []):
        out.append(Target(
            name=t["name"], kind=t["kind"], url=t.get("url", ""), env=t.get("env", "prod"),
            authorized=bool(t.get("authorized", False)), allow_active=bool(t.get("allow_active", False)),
            app=t.get("app", ""), token=t.get("token", ""), headers=t.get("headers", {}),
            options=t.get("options", {})))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run Argus dynamic (DAST) scans against running services.")
    ap.add_argument("--config", default=str(ROOT / "config" / "dast.json"))
    ap.add_argument("--target", action="append", help="only this target name (repeatable)")
    ap.add_argument("--active", action="store_true", help="run intrusive/active checks (fuzzing, abuse, rate probing)")
    ap.add_argument("--allow-prod-active", action="store_true",
                    help="permit active checks against a prod target that opts in (allow_active). Use with care.")
    ap.add_argument("--out", default=str(ROOT / "reports"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    targets = load_targets(args.config)
    if args.target:
        targets = [t for t in targets if t.name in set(args.target)]
    if not targets:
        print("No targets in %s. Add one (see config/dast.example.json) and mark it authorized." % args.config,
              file=sys.stderr)
        return 2

    run = {"generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
           "version": "1.0.0", "mode": "dast", "apps": []}
    by_app = {}
    for t in targets:
        mod_name = SCANNERS.get(t.kind)
        entry = by_app.setdefault(t.app or t.name, {"app": t.app or t.name, "repo": "", "findings": [],
                                                    "skipped": [], "errored": []})
        if not mod_name:
            entry["errored"].append({"scanner": t.kind, "note": "unknown kind %r" % t.kind})
            continue
        module = importlib.import_module(mod_name)
        if args.verbose:
            print("  [%s] %s -> %s (%s)" % (t.app, t.kind, t.url or t.name, t.env), file=sys.stderr, flush=True)
        start = time.time()
        try:
            found = module.scan(t, intrusive=args.active, allow_prod_active=args.allow_prod_active)
            for f in found:
                f.app = f.app or t.app
            entry["findings"] += [f.to_dict() for f in found]
            if args.verbose:
                print("    %d findings (%.1fs)" % (len(found), time.time() - start), file=sys.stderr, flush=True)
        except NotAuthorized as e:
            entry["skipped"].append("%s: %s" % (t.kind, e))
            if args.verbose:
                print("    skipped: %s" % e, file=sys.stderr, flush=True)
        except Exception as e:
            entry["errored"].append({"scanner": t.kind, "note": str(e)})
            if args.verbose:
                print("    ERROR: %s\n%s" % (e, traceback.format_exc()), file=sys.stderr, flush=True)
    run["apps"] = list(by_app.values())

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report.write_json(run, out / "dast-findings.json")
    report.write_sarif(run["apps"], out / "dast-findings.sarif")
    report.write_markdown(run, out / "dast-report.md")
    print("DAST reports written to %s" % out, file=sys.stderr)
    live = [RANK[f["severity"]] for app in run["apps"] for f in app["findings"] if not f.get("suppressed")]
    return 1 if (live and min(live) <= RANK["high"]) else 0


if __name__ == "__main__":
    sys.exit(main())
