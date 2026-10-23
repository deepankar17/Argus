"""Dynamic Firebase rules testing against the local emulator. The emulator is a throwaway local
process — never production — so this is safe to run.

If the app ships a rules test suite (e.g. phoniq/firestore-tests), this runs it under the emulator
with `firebase emulators:exec` and reports a failing suite as a finding: those tests assert that
unauthorized reads/writes are denied, so a failure is a real rule gap. If the app has rules but no
test suite, it emits guidance to add one (the static firebase-rules scanner still covers the rules
text statically).
"""
import json
import os
import re
from pathlib import Path

from ..core import Finding
from .core import Target, authorize
from .shared import run_tool, tool_available

NAME = "firebase-rules-dynamic"
CATEGORY = "Firebase rules (dynamic)"


def _env_with_java():
    """The Firebase emulator needs a JRE. Homebrew's openjdk is keg-only (not on the default PATH),
    so put it on PATH here if it exists, rather than requiring a shell-profile change."""
    env = dict(os.environ)
    for jdk in ("/opt/homebrew/opt/openjdk/bin", "/usr/local/opt/openjdk/bin"):
        if Path(jdk).exists():
            env["PATH"] = jdk + os.pathsep + env.get("PATH", "")
            env.setdefault("JAVA_HOME", str(Path(jdk).parent / "libexec/openjdk.jdk/Contents/Home"))
            break
    return env


def _test_command(app_path):
    """(dir, run-cmd list, self_wraps) for the app's rules tests, or (None, None, False).
    self_wraps is True when the test script already starts the emulator itself (emulators:exec)."""
    for d in ("firestore-tests", "firebase/firestore-tests", "test/rules", "rules-tests"):
        pkg = app_path / d / "package.json"
        if pkg.exists():
            try:
                scripts = json.loads(pkg.read_text()).get("scripts", {})
            except ValueError:
                scripts = {}
            if "test" in scripts:
                return d, ["npm", "test"], "emulators:exec" in scripts["test"]
    return None, None, False


def scan(target: Target, intrusive: bool = False, allow_prod_active: bool = False):
    # Emulator work is local; mark env local so the gate is happy, but still require authorization.
    authorize(target, intrusive=False, allow_prod_active=allow_prod_active)
    app_path = Path(os.path.expanduser(target.options.get("path", target.url)))
    if not app_path.exists():
        return [Finding(NAME, "no-path", "info", "No local checkout path for %s" % target.app, category=CATEGORY,
                        app=target.app)]
    if not tool_available("firebase"):
        return [Finding(NAME, "tool-missing", "info", "firebase CLI not installed (npm i -g firebase-tools)",
                        category=CATEGORY, app=target.app)]
    rel, cmd, self_wraps = _test_command(app_path)
    if not cmd:
        has_rules = any((app_path).glob("*.rules")) or "firestore" in (
            (app_path / "firebase.json").read_text() if (app_path / "firebase.json").exists() else "")
        if has_rules:
            return [Finding(NAME, "no-rules-tests", "low", "%s has Firestore rules but no emulator test suite" % target.app,
                            "firebase.json", category=CATEGORY, app=target.app,
                            detail="Dynamic rule testing (attempting denied reads/writes in the emulator) is the "
                                   "surest way to catch rule gaps.",
                            fix="Add a @firebase/rules-unit-testing suite and wire it to `firebase emulators:exec`.")]
        return [Finding(NAME, "no-rules", "info", "No Firestore rules found for %s" % target.app, category=CATEGORY,
                        app=target.app)]
    test_dir = app_path / rel
    # Ensure deps, then run the suite. If the script starts the emulator itself, run it directly;
    # otherwise wrap it in `firebase emulators:exec`.
    if not (test_dir / "node_modules").exists():
        run_tool(["npm", "ci"], cwd=str(test_dir), timeout=1200, ok_codes=range(0, 256))
    full = cmd if self_wraps else ["firebase", "emulators:exec", "--only", "firestore",
                                   "--project", "argus-dast-test", " ".join(cmd)]
    out = run_tool(full, cwd=str(test_dir), timeout=1800, ok_codes=range(0, 256), env=_env_with_java())
    log = (out.stdout + out.stderr)
    if out.returncode == 0:
        return [Finding(NAME, "rules-tests-pass", "info", "%s rules tests pass in the emulator" % target.app,
                        category=CATEGORY, app=target.app)]
    # A non-zero exit is only a rule gap if the suite actually ran and a test failed. Setup/tooling
    # errors (no Java, emulator port busy, missing deps) are reported as "could not run", not as a
    # security finding, so the tool never raises a false alarm.
    SETUP = ("Unable to locate a Java Runtime", "java -version", "command not found", "Cannot find module",
             "EADDRINUSE", "address already in use", "Could not start", "npm error", "ENOENT",
             "emulators: Could not", "Please make sure Java")
    fails = re.findall(r"^\s*(?:\d+\)|✗|×|✘|FAIL|not ok|AssertionError|Expected).*$", log, re.M)[:15]
    if fails and not any(m in log for m in SETUP):
        return [Finding(NAME, "rules-tests-fail", "high", "%s rules tests FAIL in the emulator" % target.app,
                        rel, category=CATEGORY, app=target.app,
                        detail="A failing rules test means an unauthorized operation was NOT denied:\n"
                               + "\n".join(fails)[:1500],
                        fix="Fix the rules so the denied cases fail closed; re-run.")]
    reason = next((m for m in SETUP if m in log), "the suite did not complete")
    return [Finding(NAME, "rules-tests-did-not-run", "info",
                    "%s rules tests could not run (%s)" % (target.app, reason), rel, category=CATEGORY,
                    app=target.app, detail=log.strip()[-800:],
                    fix="Install the prerequisite (the Firebase emulator needs a Java runtime: `brew install openjdk`) "
                        "and re-run; this is a setup issue, not a rules finding.")]
