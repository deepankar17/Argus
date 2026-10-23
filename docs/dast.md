# Dynamic testing (DAST)

The static scanners (`./argus`) read code and configs. The dynamic scanners (`./argus-dast`) test
**running** services — a deployed site, an HTTP function, the MCP server, or the Firebase emulator.
Because they touch live systems, they are deliberately separate and gated.

## The safety gate

Nothing runs unless you ask for it. Every target lives in `config/dast.json` and runs only when:

- `authorized: true` is set on it, and
- for **active / intrusive** checks (`--active`): the target's `env` is `local` or `staging`, **or**
  the target sets `allow_active: true` **and** the run uses `--allow-prod-active`.

So a plain `./argus-dast` does passive checks against authorized targets; intrusive testing against
production takes two explicit opt-ins. A target that isn't authorized, or a prod target you try to
actively scan without the flags, is **skipped with a reason**, never run.

Put real tokens in an environment variable and reference them (`"token": "${CREWCHAT_TOKEN}"`); do
not commit them.

## The scanners

| kind | tool | what it does | intrusive? |
|---|---|---|---|
| `web` | nuclei, OWASP ZAP | template checks (misconfig, exposures, known CVEs) and, on `--active`, a full spider+attack scan | passive by default; `--active` adds fuzzing |
| `tls` | sslyze | protocols and certificate of the host (SSLv3/TLS1.0/1.1 still on, cert/chain/hostname) | never (read-only) |
| `http-api` | built-in | live security headers, CORS reflection, error leaks, and (on `--active`) one bounded oversized-body check | mostly passive; one bounded probe on `--active` |
| `mcp` | built-in | MCP posture: token required, loopback-only bind, same-origin writes, and (on `--active`) body-limit and error-hygiene | posture passive; two bounded probes on `--active` |
| `firebase-emulator` | firebase CLI + your rules tests | runs your `@firebase/rules-unit-testing` suite in the **local emulator** and reports a failing suite as a rule gap | never (local emulator only) |

The `mcp` and `firebase-emulator` checks are meant for a **local throwaway instance**, not a live
server — start CrewChat with its own `CREWCHAT_HOME` and a spare port, and the emulator is a local
process the firebase CLI starts and tears down.

## Running it

```bash
./argus-dast                       # passive checks, every authorized target
./argus-dast --target phoniq-rules # one target
./argus-dast --active              # add intrusive checks (local/staging targets only)
./argus-dast --active --allow-prod-active   # also active against prod targets that opted in — use with care
```

Reports: `reports/dast-report.md`, `dast-findings.json`, `dast-findings.sarif`.

## Note on active testing against production

Active DAST sends attack-shaped traffic (fuzzing, injection probes, rate testing). Against a live
production app that can corrupt data, trip abuse limits, or run up a bill. Prefer a staging or
throwaway instance; if you must test prod, do it in a maintenance window, with the two opt-in flags,
and expect the gate to make you say so explicitly per target.

## Android deep analysis (MobSF)

`kind: "mobsf"` runs [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) in a local
Docker container against a **built** APK/AAB and maps its `appsec` summary (signing/debug cert,
crypto misuse, exported components, hardcoded secrets, insecure storage/RNG, trackers, risky
network destinations, permissions) into findings. Point the target at the artifact:

```json
{ "name": "phoniq-apk", "app": "phoniq", "kind": "mobsf", "env": "local", "authorized": true,
  "options": { "artifacts": ["~/path/to/app-release.apk"] } }
```

Needs Docker running (Docker Desktop, or Colima: `brew install colima docker && colima start`).
MobSF analyses APKs far more completely than AABs — prefer a (release) APK. Analysis is static and
local; the container never uploads the app.
