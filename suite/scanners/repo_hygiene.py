"""Repository hygiene: sensitive files that are committed, or sitting in the folder where one
`git add .` would commit them."""
import re
import subprocess

from ..core import Finding

NAME = "repo-hygiene"
CATEGORY = "Repository hygiene"

# (pattern, severity if committed, what it is)
SENSITIVE = [
    (r"\.(jks|keystore|p12|pfx)$", "critical", "a signing keystore"),
    (r"(^|/)keystore\.properties$", "high", "keystore passwords"),
    (r"(^|/)key\.properties$", "high", "keystore passwords (Flutter)"),
    (r"(^|/)\.env(\.[\w-]+)?$", "high", "an environment file"),
    (r"(^|/)local\.properties$", "low", "local SDK paths (sometimes keys)"),
    (r"(service[-_]?account|firebase-adminsdk)[^/]*\.json$", "critical", "a service account key"),
    (r"\.(pem|key)$", "high", "a private key"),
    (r"(^|/)id_(rsa|ed25519|ecdsa)$", "critical", "an SSH private key"),
    (r"(^|/)\.npmrc$", "medium", "npm config (may hold an auth token)"),
    (r"(^|/)\.pypirc$", "high", "PyPI credentials"),
    (r"\.mobileprovision$", "medium", "an iOS provisioning profile"),
    (r"(^|/)credentials(\.json)?$", "high", "credentials"),
    (r"(^|/)token\.json$", "high", "an OAuth token"),
]
EXAMPLE = re.compile(r"(\.example|\.sample|\.template|\.dist)$|(^|/)(test|tests|fixtures?)/")
SKIP = re.compile(r"(^|/)(build|node_modules|\.gradle|\.dart_tool|Pods|\.git)/")


def _git(root, *args):
    out = subprocess.run(["git", "-C", str(root)] + list(args), capture_output=True, text=True)
    return [f for f in out.stdout.split("\0") if f] if out.returncode == 0 else None


def scan(app):
    tracked = _git(app.path, "ls-files", "-z")
    if tracked is None:
        return [Finding(NAME, "not-git", "info", "Not a git checkout; hygiene checks skipped", category=CATEGORY)]
    untracked = _git(app.path, "ls-files", "-z", "--others", "--exclude-standard") or []
    findings = []
    for files, committed in ((tracked, True), (untracked, False)):
        for f in files:
            if SKIP.search(f) or EXAMPLE.search(f):
                continue
            for pattern, sev, what in SENSITIVE:
                if re.search(pattern, f, re.I):
                    if committed:
                        findings.append(Finding(NAME, "committed-sensitive-file", sev, "%s is committed (%s)" % (f, what),
                                                f, category=CATEGORY,
                                                detail="Everyone with read access to the repo, and every clone, has it.",
                                                fix="Rotate what it holds, git rm --cached it, and add it to .gitignore."))
                    else:
                        findings.append(Finding(NAME, "unignored-sensitive-file", "medium",
                                                "%s is not git-ignored (%s)" % (f, what), f, category=CATEGORY,
                                                detail="It is not committed yet, but git add . would commit it.",
                                                fix="Add it to .gitignore."))
                    break
    gi = app.path / ".gitignore"
    if not gi.exists():
        findings.append(Finding(NAME, "no-gitignore", "low", "No .gitignore at the repo root", category=CATEGORY))
    return findings
