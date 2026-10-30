# MinutIQ & CrewChat deep audit (step 3)

_2026-10-28. Read against `~/MinutIQ` and `~/AndroidStudioProjects/crewchat` after the Flawhound static
+ dynamic sweeps (MobSF, nuclei/ZAP, MCP posture). This is the judgment pass: what is real in each
app today, and what the scanner findings got wrong._

## Verdict

Neither app has an app-code security bug that needs a patch right now. Every crypto / SQL / file
finding the scanners raised is either in a bundled third-party library (not the app's own code) or
a safe pattern the tool misread. The real, non-code items are owner tasks (a MinutIQ release
keystore, Firebase console hardening, the crewchat.dev TLS edge) and one known MinutIQ feature
backlog item (database encryption at rest).

---

## MinutIQ

### Crypto / RNG / SHA-1 — not in app code
MobSF flagged CBC/PKCS5 padding, SHA-1 and an insecure RNG. All of them are in **bundled Flutter
plugins** (`com.dexterous.flutterlocalnotifications`, `com.bbflight.background_downloader`, gRPC
internals, and obfuscated `defpackage/*`), not in MinutIQ's code. MinutIQ's own `lib/` (Dart) and
`android/app/src` (Kotlin) contain **no** `Cipher`/AES/CBC, SHA-1/MD5, or `Random()`/`SecureRandom`
usage. There is nothing to change in the app; keep the plugins updated.

### SQL injection — false positive
MinutIQ uses **Drift** (type-safe, parameterized). The only raw statements in `lib/data/db/
app_database.dart` are `VACUUM` and `PRAGMA wal_checkpoint(TRUNCATE)` — static, no input. The
MobSF "raw SQL / injection" finding was from a plugin, not MinutIQ.

### Release signed with a debug certificate — real, already in flight
The one true high from MobSF. Addressed by **PR #24** (release signing config). It needs the owner
to create the keystore (see owner steps). No further code change.

### Database not encrypted at rest — real, known backlog
`lib/data/db/app_database.dart:15` documents it: the SQLite DB (meeting transcripts, summaries,
todos) uses `NativeDatabase`, not SQLCipher. For an app whose value is private on-device meeting
data, encrypting at rest matters. It is already a planned week-3 item (swap to the SQLCipher
variant once `flutter_secure_storage` key handling is in place). **Recommendation, not a drive-by
fix** — a half-done SQLCipher migration risks the DB; do it as the planned feature with a migration
test.

### Firebase client key / App Check — console, owner
The key in `lib/firebase_options.dart` is a client identifier (ships in every app), not a leak.
Restrict it in the Google Cloud console and enforce App Check before relying on it (owner steps).

### Model download source — informational
The on-device model is fetched from `modelscope.cn` (China). Not a vulnerability, but verify
download **integrity** (checksum/signature pin) so a tampered model can't be substituted. Worth a
note in the on-device-AI research repo per the project rule.

---

## CrewChat

Both code-review items from the scan are **false positives**, confirmed by reading the code.

### File permissions — false positive
`crewchat.py` creates every sensitive file with `0o600` and directories with `0o700`
(`os.open(..., 0o600)`, `os.fchmod(fd, 0o600)` to repair files an older version left readable,
`mkdir(mode=0o700)`), and the token store is explicitly `0o700`. The one `0o644` is deliberate, for
non-private files via `0o600 if private else 0o644`. SECURITY.md's claim holds.

### Raw SQL (`crewchat_map.py`) — false positive
Every query uses `?` bind parameters. Lines 733 and 833 use `%`-formatting only to build the
placeholder list itself (`",".join("?" * len(chunk))`) and pass the values as bound params
(`chunk`) — the correct parameterized-`IN` pattern, no user data in the SQL string. `executescript`
runs the static `SCHEMA` and literal `DELETE FROM` constants.

### MCP server — passed dynamic posture checks
From the earlier DAST run: token required, loopback-only bind, rejects unauthenticated cross-origin,
caps body size, clean errors. The `curl | sh` in `.github/workflows/new-user.yml` is intentional
(that workflow exists to test the README's install command on fresh machines) — not a finding.

### Nothing to change in CrewChat code.

---

## What this leaves (all owner / platform, or planned feature)
1. MinutIQ: create the release keystore + `key.properties` (then PR #24 confirms).
2. GitHub Actions billing (so CI runs on security PRs).
3. crewchat.dev: disable TLS 1.0/1.1 + weak ciphers at the Firebase Hosting / Fastly edge.
4. MinutIQ: restrict the Firebase API keys in the console; enforce App Check.
5. MinutIQ: database encryption at rest (SQLCipher) — planned feature, needs a migration test.
6. PhonIQ: App Check on the chat callables — deliberately off until debug tokens exist; auth + rate
   limits are the control today.
