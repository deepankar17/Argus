"""Infrastructure and config files with Trivy's misconfiguration scanner: Dockerfiles, Terraform,
Kubernetes, CloudFormation, Helm and the like."""
import tempfile
from pathlib import Path

from ..core import Finding, load_json, need, run, tracked_set

NAME = "iac"
CATEGORY = "Infrastructure as code"
SKIP_DIRS = ["build", "node_modules", ".gradle", ".dart_tool", "dist", "Pods", ".git", ".npu-work",
             ".claude", "android-ndk*", "qairt"]


def scan(app):
    need("trivy", "brew install trivy")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "trivy.json"
        cmd = ["trivy", "fs", "--quiet", "--scanners", "misconfig", "--format", "json", "--output", str(out),
               "--exit-code", "0"]
        for d in SKIP_DIRS:
            cmd += ["--skip-dirs", "**/%s" % d]
        run(cmd + [str(app.path)], timeout=1800)
        data = load_json(out) or {}
    tracked = tracked_set(app.path)
    findings = []
    for res in data.get("Results", []) or []:
        target = res.get("Target", "")
        if tracked is not None and target not in tracked:
            continue  # untracked vendored/scratch config is not this repo's
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            cause = m.get("CauseMetadata") or {}
            findings.append(Finding(
                NAME, m.get("ID", m.get("AVDID", "misconfig")), m.get("Severity", "medium"),
                "%s (%s)" % (m.get("Title", ""), target), target, cause.get("StartLine", 0), category=CATEGORY,
                detail=m.get("Message") or m.get("Description", ""), fix=m.get("Resolution", ""),
                references=m.get("References", [])[:3]))
    return findings
