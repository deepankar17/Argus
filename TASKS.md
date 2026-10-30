# Flawhound — task list

Open tasks from the security work. Checkbox = done. See [`HANDOVER.md`](HANDOVER.md) for detail.
Owners: **Deepankar** (keys, console, billing, merges) · **app dev** (code fixes in each app repo).

_Last reconciled 2026-10-28 against the actual repo state. All remaining open items are owner-only
(keys, billing, console) or a planned MinutIQ feature; the code audits are complete._

## Done 2026-10-29
- [x] **MinutIQ release keystore + `android/key.properties`** — created (`~/minutiq-release.jks`, alias `minutiq`, RSA-2048, 10000d; key.properties is 0600 and git-ignored). **A release build now signs with the release key** (verified: APK signer DN `CN=MinutIQ`, SHA-1 `91:8D:D3:…`), so the debug-cert finding is fixed and PR #24 is confirmed working.
  - ⚠️ **BACK UP** `~/minutiq-release.jks` **and** `~/MinutIQ/android/key.properties` (which holds the passwords) somewhere safe and off this machine. If you publish to Play with this key and later lose it, you can't update the app. (Or switch to Play App Signing, where Google holds the key and this becomes just the upload key.)
- [x] **MinutIQ Firebase console — API keys restricted** (both app-restricted + the existing 25-API restriction):
  - **iOS key** → iOS apps, bundle `com.minutiq.minutiq`.
  - **Android key** → Android apps, package `com.minutiq.app` with **both** the release SHA-1 (`91:8D:D3:…`) and the debug SHA-1 (`5E:68:99:…`), so production and dev builds both work.

## Owner-only — still only Deepankar can do these
- [ ] **Unblock GitHub Actions billing** so CI runs on the security PRs. — _Deepankar · org/billing_
  - GitHub → Settings → Billing and plans → add/confirm a payment method (or raise the Actions spending limit). Then re-run the checks on any open PR.
- [ ] **crewchat.dev TLS**: crewchat.dev is served through **Cloudflare** (confirmed: NS `*.ns.cloudflare.com`, `server: cloudflare`), so the TLS 1.0/1.1 + weak-cipher finding is a **Cloudflare setting**, one click: Cloudflare dashboard → the `crewchat.dev` zone → **SSL/TLS → Edge Certificates → Minimum TLS Version → set to TLS 1.2**. (I can do this in Chrome once you're signed into Cloudflare there — I won't enter the login myself.) — _Deepankar / Claude once signed in · Cloudflare_
- [ ] **MinutIQ App Check** — left off deliberately: the app doesn't call the App Check SDK yet, so enforcing it now would lock the app out of Firebase. Do after the SDK is integrated. — _Deepankar · MinutIQ / console_

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
- [x] Build Flawhound (static suite: 9 scanners) — `deepankar17/Flawhound`
- [x] Build the DAST module (web/nuclei+ZAP, TLS, HTTP-API, MCP, Firebase-emulator, MobSF)
- [x] Full static + dynamic sweep of PhonIQ, CrewChat, MinutIQ
- [x] Handover doc + agent guide + published task page
