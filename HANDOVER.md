# Argus — handover

Security suite for the owner's apps — **PhonIQ**, **CrewChat**, **MinutIQ** — plus the findings and
fixes from the first full run. Written so the work can continue in Cursor (or any editor/agent).

- **Repo:** `deepankar17/Argus` (private) · **local:** `/Users/deepankar/argus`
- **Last run:** 2026-10-24. Static + dynamic (DAST) complete on all three apps.
- Companion docs: [`README.md`](README.md), [`docs/scanners.md`](docs/scanners.md) (static),
  [`docs/dast.md`](docs/dast.md) (dynamic).

---

## 1. What Argus is

One command scans each app and writes a ranked report. **Static** (`./argus`) reads code/config and
is safe to run anytime. **Dynamic** (`./argus-dast`) tests *running* services and is gated so it
can't attack production by accident. Each app declares its stack in `config/apps.json`; only the
relevant scanners run.

### Layout
```
argus/
  argus              # static entry point  -> suite/runner.py
  argus-dast         # dynamic entry point -> suite/dast_runner.py
  suite/
    core.py          # Finding model, severity, git helpers
    runner.py        # static orchestrator
    report.py        # JSON + SARIF + Markdown reports
    scanners/        # static scanners (one module each, NAME + scan(app))
      secrets.py repo_hygiene.py sca.py sast.py iac.py
      firebase_rules.py firebase_config.py android.py llm_static.py
    dast/            # dynamic scanners (NAME + scan(target, intrusive, allow_prod_active))
      core.py        # Target model + authorize() gate  <- the safety boundary
      web.py tls.py http_api.py mcp_dynamic.py firebase_rules_dynamic.py mobsf.py
    dast_runner.py   # dynamic orchestrator
  rules/
    gitleaks.toml    # secrets config + allowlists (test fixtures, Firebase client keys, etc.)
    semgrep/mcp.yaml # custom Semgrep rules (MCP, subprocess, weak compare, yaml.load)
  config/
    apps.json        # the three apps + their kinds  (committed)
    dast.json        # DAST targets, AUTHORIZED + real hostnames  (git-IGNORED, lives locally)
    dast.example.json# template for dast.json  (committed)
    suppressions.json# static false-positive suppressions (by fingerprint or scanner/rule)
  tests/test_analyzers.py   # 20 unit tests (pure-Python analyzers + the DAST gate)
  reports/           # run output (git-ignored): report.md, findings.json, findings.sarif
```

### Add a scanner
A scanner is a module with `NAME` and `scan(...) -> list[Finding]`. Add it to `SCANNERS` in
`suite/runner.py` (static, with the app kinds it applies to) or `suite/dast_runner.py` (dynamic).
Findings use the `Finding` dataclass in `suite/core.py`.

---

## 2. How to run it

### Prerequisites (already installed on this Mac)
```bash
brew install gitleaks trivy osv-scanner semgrep nuclei testssl colima docker
python3 -m pip install --user sslyze            # DAST TLS
brew install openjdk                            # Firebase emulator needs a JRE (keg-only)
```
Python 3.9+, standard library only (the suite shells out to the tools above). A missing tool makes
its scanner **skip**, not fail.

### Static
```bash
cd ~/argus
./argus                 # all apps, all applicable scanners
./argus --app phoniq -v
./argus --scanner sast
./argus --fail-on critical   # CI gate (default: high)
```

### Dynamic (DAST)
Targets live in `config/dast.json` (git-ignored; already filled in locally with the real hosts).
Nothing runs unless a target has `authorized: true`, and **active** scans are refused against a
`prod` target unless it sets `allow_active: true` **and** the run passes `--allow-prod-active`.
```bash
colima start                         # bring Docker up first (MobSF + ZAP need it)
./argus-dast                         # passive checks, authorized targets
./argus-dast --target phoniq-rules   # one target (Firestore rules in the emulator)
./argus-dast --active --allow-prod-active   # full active incl. prod (owner-authorized)
```
DAST reports: `reports/dast-report.md`, `dast-findings.json`, `dast-findings.sarif`.

### Tests
```bash
python3 tests/test_analyzers.py      # expect 20/20
```

---

## 3. Target inventory (from the apps' own docs)

| App | Firebase project | Web / endpoint | Notes |
|---|---|---|---|
| **PhonIQ** | `phoniq-app` | `https://phoniq.app`, `https://phoniq.app/api/web-error` (`webError`, `asia-south1`) | Android + Firebase Hosting/Functions. Firestore rules + emulator tests in `firestore-tests/`. |
| **CrewChat** | `crewchat-ae908` (hosting site `crewchat-chat`) | `https://crewchat.dev` (+ `/demo/`) | Python MCP server, **loopback-only** (127.0.0.1:8765, token per folder, reached over Tailscale). Dev in `crewchat-dev` on branch `dev`. No Cloud Functions. |
| **MinutIQ** | `minutiq-app` | — none — | Fully on-device (Whisper/sherpa-onnx). Firebase = Crashlytics only (Auth/App Check planned). No web/server surface. |

No staging environment exists — every live target is production.

---

## 4. Findings status

### Static (`./argus`): 161 findings — 1 critical, 27 high, 84 medium, rest low/info
- **PhonIQ (83):** most highs are known CVEs in `firestore-tests/` **dev deps** (not shipped) →
  fixed, see PR below. Real in-app: exported Android components w/o permission; Firestore
  `users/{uid}` readable by any signed-in user (confirm intended — public keys for the courier);
  App Check not enforced on callables (the code's own TODO).
- **CrewChat (69):** mostly expected for a launcher (subprocess/urllib). One GH Actions `curl|sh`
  that is **intentional** (its `new-user.yml` tests the README install command — false positive).
  Worth a dev's eyes: `crewchat.py` file-permissions (SECURITY.md already claims 0600, likely FP)
  and one formatted SQL in `crewchat_map.py`.
- **MinutIQ (9):** cleanest. "Secrets" flagged are the Firebase **client** config key — an
  identifier meant to ship, not a leak (Argus labels it info).

### Dynamic (`./argus-dast`)
- **Web (nuclei + OWASP ZAP active):** no injection/XSS/auth holes on either site (static Hosting).
  Real items are CDN/platform-layer: crewchat.dev accepts **TLS 1.0/1.1 + weak ciphers**; both sites
  reflect **Fastly debug headers**; **CSP `style-src 'unsafe-inline'`** and **missing SRI** on the
  Cloudflare script (phoniq.app). phoniq `/api/web-error` is solid (rejects oversized body; CORS OK).
- **CrewChat MCP (local throwaway instance):** passes all posture checks — token required,
  loopback-only, rejects unauthenticated cross-origin, body cap, clean errors.
- **Firebase rules (emulator):** PhonIQ's Firestore rules correctly **deny** unauthorized
  reads/writes (verified by attempting them).
- **MobSF (Android):**
  - **MinutIQ release APK: signed with a DEBUG certificate (HIGH)** + CBC/PKCS padding; plus SQLite
    raw query, SHA-1, insecure RNG, external storage, a model server in China (`modelscope.cn`).
  - **PhonIQ:** scanned the debug APK (release is an AAB; release config is clean per the static
    scan). Real app item: **CBC/PKCS padding in `CallRecorder`/`CallRecordingPlayer`**. The 100+
    exported activity-aliases are launcher skins (exported by design).

---

## 5. Open PRs (draft, assigned to deepankar17)

| Repo | PR | What |
|---|---|---|
| `deepankar17/PhonIQ` | **#5** `security/bump-firestore-test-deps` | `npm audit fix` in `firestore-tests` — clears the high-sev body-parser DoS; rules tests pass. |
| `deepankar17/MinutIQ` | **#24** `security/release-signing-config` | Proper release signing (reads `android/key.properties`, falls back to debug locally). **You must create the keystore + `key.properties`** — see the PR body / `android/key.properties.example`. |

> Project context (from the coordinator): GitHub Actions billing may be disabled, so CI won't run on
> these PRs automatically — merge/verify locally. Action-pinning (SHA-pinning workflows) was **not**
> opened as a PR for the same reason; do it when billing is sorted if you want it.

---

## 6. What's left (handed to per-app judgment, not auto-fixed)

These were deliberately **not** auto-fixed because they need app knowledge or could break behaviour:
- **Crypto:** replace CBC/PKCS5 with an AEAD mode (e.g. AES-GCM) in PhonIQ `CallRecorder`/
  `CallRecordingPlayer` and in MinutIQ; review SHA-1 and insecure-RNG usages (some are in libs).
- **Exported Android components (PhonIQ):** 2 services + a few receivers (CarAppService,
  Boot/Alarm/ModelDownload/MissedCall). Some *must* stay exported (Android Auto, system
  broadcasts) — decide per component: `exported=false` or a signature permission, else leave.
- **Web headers:** tighten CSP (drop `style-src 'unsafe-inline'` via hashes/nonces) and add SRI to
  the Cloudflare script in `firebase.json`/hosting — verify rendering after.
- **crewchat.dev TLS 1.0/1.1 + weak ciphers:** Firebase Hosting/Fastly edge config, not app code.
- **MinutIQ:** restrict the Firebase API keys in the Google Cloud console (per `docs/SETUP_NEEDED.md`);
  commit Security Rules if any Firestore/Storage use is added; enforce App Check before relying on it.

---

## 7. Next steps / cross-references

1. **Create the MinutIQ release keystore** and `android/key.properties`, then build a signed release
   to confirm PR #24 (the single most important fix).
2. Merge PR #5 (dev-dep bump) once CI is unblocked.
3. Work the "left" list above per app — each app's repo is the right place.
4. **Deep PhonIQ audit not started:** the separate "Help me work out a plan for a project" thread was
   about to begin *step 2 — the deep PhonIQ audit* — and it has **not** started yet. Pick that up
   there; Argus is the tooling for it.
5. Re-run anytime: `./argus` for static, `colima start && ./argus-dast --active --allow-prod-active`
   for the full dynamic sweep. Keep `tests/test_analyzers.py` green when editing analyzers.

---

## 8. Design principles (so changes keep the tool credible)
- **Low false-positive bar.** Scan only git-tracked files; Firebase client keys are info, not
  secrets; test fixtures and localized zero-width joiners are allowlisted; a regression test asserts
  Argus does **not** flag PhonIQ's real Firestore rules. Keep this bar when adding rules.
- **DAST is gated.** Never weaken `suite/dast/core.py:authorize()`. Active-against-prod needs two
  explicit opt-ins.
- **Static + local only by default.** No telemetry; SCA sends only package name+version to OSV.dev;
  Semgrep metrics off; MobSF runs locally and never uploads the app.
