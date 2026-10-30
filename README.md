# Flawhound

[![Sponsor](https://img.shields.io/github/sponsors/deepankar17?label=Sponsor&logo=github)](https://github.com/sponsors/deepankar17)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-tip-FF5E5B?logo=kofi&logoColor=white)](https://ko-fi.com/deepankarsarkar)

A defensive, end-to-end security test suite for my own apps — **PhonIQ**, **CrewChat** and
**MinutIQ**. One command scans every app, applies the right checks for each stack, and writes a
single ranked report.

It is built to be run on my own code, from my machine or CI. It does **static** analysis and
config review only; it does not attack live services, send traffic to production, or run intrusive
scans.

## What it checks

| Scanner | Tool | Looks for |
|---|---|---|
| `secrets` | [gitleaks] | API keys, tokens and passwords in the working tree **and the whole git history** (redacted in reports) |
| `repo-hygiene` | git | Keystores, `.env`, service-account keys, private keys committed or sitting un-ignored |
| `sca` | [osv-scanner] + OSV.dev | Known-vulnerable dependencies (npm, pub, pip, and the Gradle version catalog) |
| `sast` | [semgrep] | Code bugs: injection, XSS, crypto, path traversal, SSRF (community rulesets + this repo's own rules) |
| `iac` | [trivy] | Misconfigured Dockerfiles, Terraform, Kubernetes, etc. |
| `firebase-rules` | built-in | Firestore / Storage / RTDB rules that let anyone, or any signed-in user, read or write others' data; test-mode rules; unvalidated writes |
| `firebase-config` | built-in | Hosting security headers and CSP; Cloud Functions with no auth check, no App Check, wide-open CORS, or no `maxInstances` |
| `android` | built-in | `debuggable`/`allowBackup` releases, cleartext traffic, exported components with no permission, user-CA trust, un-minified releases, hardcoded signing passwords |
| `llm-static` | built-in + semgrep | Hidden Unicode (Trojan Source / ASCII smuggling) and prompt-injection text in files AI agents read (`CLAUDE.md`, skills, prompts), MCP tool-description poisoning, MCP configs committed with a token, servers binding all interfaces, `shell=True` |

Each app in [`config/apps.json`](config/apps.json) declares its `kinds` (android, flutter, python,
firebase, firebase-functions, web, mcp); only the scanners that apply to a kind run.

## Install

```bash
brew install gitleaks trivy osv-scanner semgrep
```

Python 3.9+ only, standard library (the suite shells out to the tools above). Scanners whose tool
is missing are reported as **skipped**, not failed, so a partial toolbox still gives a partial report.

## Run

```bash
./flawhound                 # every app, every applicable scanner
./flawhound --app phoniq -v # one app, verbose
./flawhound --scanner sast  # one scanner across all apps
./flawhound --fail-on critical   # exit non-zero only on critical (default: high) — for CI gates
```

Reports land in `reports/`:
- `report.md` — ranked, readable, grouped by app and category
- `findings.json` — every finding with a stable `fingerprint`
- `findings.sarif` — for GitHub code scanning / editors

## Dynamic testing (DAST)

`./flawhound` is static. To test **running** services — a deployed site, an HTTP function, the MCP
server, or Firebase rules in the emulator — use `./flawhound-dast`. It drives nuclei, OWASP ZAP, sslyze
and the Firebase emulator, and is **gated**: a target runs only when marked `authorized` in
`config/dast.json`, and intrusive/active scans are refused against a `prod` target unless it opts in
and the run passes `--allow-prod-active`.

```bash
./flawhound-dast                 # passive checks against authorized targets
./flawhound-dast --active        # add intrusive checks (local/staging targets only)
```

See [docs/dast.md](docs/dast.md) for the target config and the safety model. Copy
`config/dast.example.json` to `config/dast.json` (git-ignored) and fill in your targets.

## Quieting a false positive

Add an entry to [`config/suppressions.json`](config/suppressions.json) — by `fingerprint` (copied
from `findings.json`) or by `scanner`/`rule`/`file` — always with a `reason`. Suppressed findings
still appear in the report, folded away, so nothing is hidden silently.

## Extending

A scanner is a module in [`suite/scanners/`](suite/scanners/) with a `NAME` and a
`scan(app) -> list[Finding]`. Add it to `SCANNERS` in [`suite/runner.py`](suite/runner.py) with the
app kinds it applies to. Add Semgrep rules under [`rules/semgrep/`](rules/semgrep/).

## Tests

```bash
python3 tests/test_analyzers.py   # the built-in analyzers, incl. a no-false-alarm check on real rules
```

## Scope and safety

- Static and config review only. No DAST, no live-service probing, no destructive actions.
- Dependency SCA sends only package names and versions to OSV.dev; Semgrep metrics are off and code
  never leaves the machine.
- Secrets are redacted before they reach any report.

[gitleaks]: https://github.com/gitleaks/gitleaks
[osv-scanner]: https://github.com/google/osv-scanner
[semgrep]: https://semgrep.dev
[trivy]: https://github.com/aquasecurity/trivy
