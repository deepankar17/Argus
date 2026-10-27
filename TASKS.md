# Argus — task list

Open tasks from the security work. Checkbox = done. See [`HANDOVER.md`](HANDOVER.md) for detail.
Owners: **Deepankar** (keys, console, billing, merges) · **app dev** (code fixes in each app repo).

_Last reconciled 2026-10-28 against the actual repo state. All remaining open items are owner-only
(keys, billing, console) or a planned MinutIQ feature; the code audits are complete._

## Owner-only — only Deepankar can do these
- [ ] **Create the MinutIQ release keystore + `android/key.properties`**, then build a signed release to confirm PR #24. — _Deepankar · MinutIQ_
  1. `keytool -genkey -v -keystore ~/minutiq-release.jks -keyalg RSA -keysize 2048 -validity 10000 -alias minutiq` (set a store + key password; keep the `.jks` out of git).
  2. Create `~/MinutIQ/android/key.properties` (git-ignored) with `storePassword=…`, `keyPassword=…`, `keyAlias=minutiq`, `storeFile=/absolute/path/to/minutiq-release.jks` — template at `android/key.properties.example`.
  3. `cd ~/MinutIQ && flutter build apk --release` and confirm it's signed with the release key (`apksigner verify --print-certs build/app/outputs/apk/release/app-release.apk`), then mark PR #24 ready.
- [ ] **Unblock GitHub Actions billing** so CI runs on the security PRs. — _Deepankar · org/billing_
  - GitHub → Settings → Billing and plans → add/confirm a payment method (or raise the Actions spending limit). Then re-run the checks on any open PR.
- [ ] **crewchat.dev TLS**: disable TLS 1.0/1.1 + weak ciphers at the Firebase Hosting / Fastly edge (platform setting, not in the repo). — _Deepankar · crewchat-dev hosting_
- [ ] **MinutIQ Firebase console**: restrict the API keys (per `docs/SETUP_NEEDED.md` → Google Cloud console → APIs & Services → Credentials → restrict to the Android package + release SHA-1 and the Firebase Installations/Crashlytics APIs); enforce App Check once Play Integrity / App Attest are registered. — _Deepankar · MinutIQ / console_

## Audits — complete
- [x] **Deep PhonIQ audit** — [`docs/phoniq-deep-audit.md`](docs/phoniq-deep-audit.md) (2026-10-24).
- [x] **Step 3: MinutIQ + CrewChat deep audit** — [`docs/minutiq-crewchat-audit.md`](docs/minutiq-crewchat-audit.md) (2026-10-28). No app-code bug in either; all crypto/SQL/file findings are third-party-library or false positives.

## Code fixes — done or resolved
- [x] **PhonIQ crypto / backup / web headers** — shipped on `main` (commit `fe1515ae`): call recordings are AES-GCM (`CallRecordingCrypto`), cloud backup is an allowlist (`data_extraction_rules.xml`), site CSP drops `style-src 'unsafe-inline'`.
- [x] **PhonIQ dev-dep bump** — PR #5 **merged** (2026-10-24).
- [x] **Exported Android components (PhonIQ):** reviewed — leave them. Boot, exact-alarm, missed-call, Wear and Auto must stay exported; the model-download receiver only accepts this app's own download id.
- [x] **Firestore `users/{uid}` (PhonIQ):** intended — `get` of the public key for any signed-in account, no `list`, no phone hash. The 23 Oct "read every document" finding was stale.
- [x] **CrewChat review:** both items are **false positives** — all sensitive files are `0o600`/`0o700`; `crewchat_map.py` uses `?` bind params (the `%` only builds the placeholder list). Nothing to change.
- [x] **MinutIQ crypto / SQL:** not in app code — the CBC/SHA-1/RNG/raw-SQL findings are in bundled Flutter plugins; MinutIQ's own code has no such usage and uses Drift (parameterized). Keep plugins updated.
- [ ] **App Check (PhonIQ chat callables):** deliberately off until debug tokens exist; auth + rate limits are the control today. — _app dev · PhonIQ (by choice)_
- [ ] **MinutIQ DB encryption at rest (SQLCipher):** real but a planned week-3 feature, not a drive-by fix (needs `flutter_secure_storage` key handling + a migration test). — _app dev · MinutIQ_

## Done (tooling)
- [x] Build Argus (static suite: 9 scanners) — `deepankar17/Argus`
- [x] Build the DAST module (web/nuclei+ZAP, TLS, HTTP-API, MCP, Firebase-emulator, MobSF)
- [x] Full static + dynamic sweep of PhonIQ, CrewChat, MinutIQ
- [x] Handover doc + agent guide + published task page
