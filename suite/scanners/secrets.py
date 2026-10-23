"""Secrets with gitleaks: the working tree and every commit in the git history. Secrets are
redacted, so reports never carry them."""
import tempfile
from pathlib import Path

from ..core import Finding, ROOT_RULES, load_json, need, run, tracked_set

NAME = "secrets"
CATEGORY = "Secrets"


def scan(app):
    need("gitleaks", "brew install gitleaks")
    config = ROOT_RULES / "gitleaks.toml"
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        for mode in ("dir", "git"):
            if mode == "git" and not (app.path / ".git").exists():
                continue
            report = Path(tmp) / ("%s.json" % mode)
            run(["gitleaks", mode, str(app.path), "-c", str(config), "--redact", "--no-banner",
                 "--exit-code", "0", "-f", "json", "-r", str(report), "--max-target-megabytes", "5"],
                timeout=3600)
            leaks = load_json(report) or []
            tracked = tracked_set(app.path) if mode == "dir" else None
            for leak in leaks:
                path = leak.get("File", "")
                if path.startswith(str(app.path)):
                    path = path[len(str(app.path)):].lstrip("/")
                if mode == "dir":
                    # A secret on an untracked/ignored path is vendored or local-only tooling, not
                    # part of the repo. The repo-hygiene scanner handles sensitive files separately.
                    if tracked is not None and path not in tracked:
                        continue
                    title = "%s in %s" % (leak.get("Description") or leak.get("RuleID"), path)
                    findings.append(Finding(
                        NAME, leak.get("RuleID", "secret"), "high", title, path,
                        leak.get("StartLine", 0), category=CATEGORY,
                        detail="A secret in a file git tracks. Anyone with the repo has it.",
                        fix="Move it to a secret store or a git-ignored config file, and rotate it if it was ever pushed."))
                else:
                    commit = (leak.get("Commit") or "")[:10]
                    findings.append(Finding(
                        NAME, leak.get("RuleID", "secret") + ":history", "high",
                        "%s committed in %s (%s)" % (leak.get("Description") or leak.get("RuleID"), path, commit),
                        path, leak.get("StartLine", 0), category=CATEGORY,
                        detail="Commit %s by %s on %s added it. Deleting the file later does not remove it from "
                               "history." % (commit, leak.get("Author", "?"), (leak.get("Date") or "")[:10]),
                        fix="Rotate the secret first. Then rewrite history (git filter-repo) only if the repo is "
                            "private and nobody else has cloned it; otherwise rotation is the fix."))
    # The same secret is usually found in both the tree and history; keep one of each per file and rule.
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
