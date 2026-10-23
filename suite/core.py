"""Shared pieces: the Finding every scanner returns, running external tools, and fingerprints."""
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
ROOT_RULES = ROOT / "rules"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


def norm_severity(value):
    """Map the many severity spellings tools use onto ours."""
    v = str(value or "").strip().lower()
    return {
        "error": "high", "warning": "medium", "warn": "medium", "note": "low", "inventory": "info",
        "moderate": "medium", "negligible": "low", "unknown": "medium", "experiment": "info",
    }.get(v, v if v in RANK else "medium")


@dataclass
class Finding:
    scanner: str
    rule: str
    severity: str
    title: str
    file: str = ""
    line: int = 0
    detail: str = ""
    fix: str = ""
    category: str = ""
    references: List[str] = field(default_factory=list)
    app: str = ""
    suppressed: str = ""  # the reason, when a suppression matched

    def __post_init__(self):
        self.severity = norm_severity(self.severity)

    @property
    def fingerprint(self):
        """Stable across runs and line moves: scanner, rule, file and the title, not the line."""
        raw = "|".join([self.app, self.scanner, self.rule, self.file, self.title])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self):
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanResult:
    scanner: str
    status: str  # ok, skipped, error
    findings: List[Finding] = field(default_factory=list)
    note: str = ""
    seconds: float = 0.0


class Skip(Exception):
    """A scanner cannot run here (tool missing, nothing to scan). Not a failure."""


def have(tool):
    return shutil.which(tool) is not None


def need(tool, install):
    if not have(tool):
        raise Skip("%s is not installed (%s)" % (tool, install))


def run(cmd, cwd=None, timeout=1800, env=None, ok_codes=(0,)):
    """Run a tool and return CompletedProcess. Tools often exit non-zero when they find something,
    so callers pass the codes that still mean 'ran fine'."""
    full_env = dict(os.environ, **(env or {}))
    out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=full_env)
    if out.returncode not in ok_codes:
        raise RuntimeError("%s exited %d: %s" % (cmd[0], out.returncode, (out.stderr or out.stdout)[-2000:]))
    return out


def load_json(path_or_text):
    if isinstance(path_or_text, Path):
        if not path_or_text.exists() or path_or_text.stat().st_size == 0:
            return None
        path_or_text = path_or_text.read_text(errors="replace")
    text = (path_or_text or "").strip()
    return json.loads(text) if text else None


def rel(path, root):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def git_files(root):
    """Tracked files, or every file when the folder is not a git checkout."""
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, text=True)
    if out.returncode == 0:
        return [f for f in out.stdout.split("\0") if f]
    return [rel(p, root) for p in Path(root).rglob("*") if p.is_file()]


def tracked_set(root):
    """Relative paths git tracks, as a set, or None when the folder is not a git checkout. Lets a
    scanner skip untracked scratch (nested worktrees, build output, local-only copies)."""
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, text=True)
    return {f for f in out.stdout.split("\0") if f} if out.returncode == 0 else None


def line_of(text, index):
    return text.count("\n", 0, index) + 1


class App:
    """One application to test, from config/apps.json."""

    def __init__(self, name, spec, base):
        self.name = name
        self.path = Path(os.path.expanduser(spec["path"]))
        if not self.path.is_absolute():
            self.path = (base / self.path).resolve()
        self.repo = spec.get("repo", "")
        self.kinds = spec.get("kinds", [])
        self.scanners = spec.get("scanners")  # None: all that apply
        self.exclude = spec.get("exclude", [])
        self.dast = spec.get("dast", {})
        self.mcp = spec.get("mcp", {})
        self.mobsf = spec.get("mobsf", {})

    def wants(self, scanner):
        return self.scanners is None or scanner in self.scanners


def worst(findings) -> Optional[str]:
    live = [f.severity for f in findings if not f.suppressed]
    return min(live, key=RANK.get) if live else None
