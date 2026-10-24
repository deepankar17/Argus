# Argus — task list

Open tasks from the security work. Checkbox = done. See [`HANDOVER.md`](HANDOVER.md) for detail.
Owners: **Deepankar** (keys, console, billing, merges) · **app dev** (code fixes in each app repo).

## Now / blocking
- [ ] **Create the MinutIQ release keystore + `android/key.properties`**, build a signed release to confirm it no longer uses the debug cert. — _Deepankar · MinutIQ · PR #24 (draft) open_
- [ ] **Unblock GitHub Actions billing** so CI runs on the security PRs. — _Deepankar · org/billing · blocked_
- [ ] **Merge PhonIQ PR #5** (dev-dep bump in `firestore-tests`) once CI is green. — _Deepankar · PhonIQ · PR #5 (draft) open_

## Audits not yet started
- [ ] **Deep PhonIQ audit** — step 2 of the "Help me work out a plan for a project" thread; not started. Use Argus as the tooling. — _app dev · PhonIQ_
- [ ] **Step 3: MinutIQ + CrewChat deep audit** — not started. — _app dev · MinutIQ, crewchat-dev_

## Code fixes (left for app devs — need per-app judgment)
- [ ] **Crypto:** replace CBC/PKCS5 with an AEAD mode (AES-GCM) in PhonIQ `CallRecorder` / `CallRecordingPlayer` and in MinutIQ; review SHA-1 and insecure-RNG usages. — _app dev · PhonIQ, MinutIQ_
- [ ] **Exported Android components (PhonIQ):** decide per component (2 services + a few receivers — CarAppService, Boot/Alarm/ModelDownload/MissedCall): `exported=false` or a signature permission, or leave if a system integration needs it. — _app dev · PhonIQ_
- [ ] **Web headers (phoniq.app):** drop CSP `style-src 'unsafe-inline'` (use hashes/nonces) and add SRI to the Cloudflare script in `firebase.json`/hosting; verify rendering after. — _app dev · PhonIQ_
- [ ] **CrewChat review:** `crewchat.py` file-permissions (SECURITY.md already claims 0600 — likely a false positive) and one formatted SQL in `crewchat_map.py`. — _CrewChat dev · crewchat-dev (branch `dev`)_
- [ ] **Confirm PhonIQ Firestore `users/{uid}` read-by-any-signed-in-user is intended** (public keys for the courier); enforce App Check on the callables (the code's own TODO). — _app dev · PhonIQ_

## Platform / console
- [ ] **crewchat.dev TLS:** disable TLS 1.0/1.1 + weak ciphers at the Firebase Hosting / Fastly edge. — _Deepankar · crewchat-dev hosting_
- [ ] **MinutIQ Firebase:** restrict the API keys in the Google Cloud console (per `docs/SETUP_NEEDED.md`); commit Security Rules if any Firestore/Storage use is added; enforce App Check before relying on it. — _Deepankar · MinutIQ / console_

## Done
- [x] Build Argus (static suite: 9 scanners) — `deepankar17/Argus`
- [x] Build the DAST module (web/nuclei+ZAP, TLS, HTTP-API, MCP, Firebase-emulator, MobSF)
- [x] Full static + dynamic sweep of PhonIQ, CrewChat, MinutIQ
- [x] Open PhonIQ PR #5 and MinutIQ PR #24
- [x] Handover doc + agent guide for Cursor
