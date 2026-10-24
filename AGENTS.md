# Agent guide — Argus

Argus is a security suite for the apps **PhonIQ**, **CrewChat**, **MinutIQ**. Read
[`HANDOVER.md`](HANDOVER.md) first — it has the full architecture, findings, open PRs, and next
steps. This file is the short orientation for an AI agent (Cursor, etc.).

## Run
- Static: `./argus` (all apps) · `./argus --app phoniq -v` · `./argus --scanner sast`
- Dynamic: `colima start` then `./argus-dast` (passive) or `./argus-dast --active --allow-prod-active`
- Tests: `python3 tests/test_analyzers.py` — **keep this at 20/20 when editing analyzers**
- Reports land in `reports/` (git-ignored).

## Structure
- Static scanners: `suite/scanners/*.py` — each has `NAME` and `scan(app) -> list[Finding]`; registered in `suite/runner.py`.
- Dynamic scanners: `suite/dast/*.py` — each has `NAME` and `scan(target, intrusive, allow_prod_active)`; registered in `suite/dast_runner.py`.
- Shared `Finding` model + git helpers: `suite/core.py`. Reports: `suite/report.py`.
- Custom rules: `rules/gitleaks.toml`, `rules/semgrep/mcp.yaml`.
- Apps: `config/apps.json`. DAST targets: `config/dast.json` (git-ignored, real hosts) / `config/dast.example.json`.

## Rules for changes
- **Do not weaken `suite/dast/core.py:authorize()`** — it stops active scans hitting production by accident.
- Keep the false-positive bar high: scan only git-tracked files; Firebase client config keys are info, not secrets; allowlist test fixtures. A regression test asserts Argus stays silent on PhonIQ's real Firestore rules.
- Static and local only: no telemetry; SCA sends only package name+version to OSV.dev; Semgrep metrics off; MobSF/ZAP run in local Docker (Colima) and never upload the apps.
- This repo (Argus) is the tooling; fixes to the scanned apps belong in **their** repos (`deepankar17/PhonIQ`, `deepankar17/MinutIQ`, `deepankar17/crewchat-dev` — dev on branch `dev`).
