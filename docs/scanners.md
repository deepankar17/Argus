# How each scanner works, and why

The suite leans on four well-maintained open-source tools for the parts they already do best, and
adds its own analyzers for the things those tools miss for these specific apps (Firebase rules,
Android manifests, Cloud Functions, and the AI/MCP surface).

## External tools

### secrets — gitleaks
Runs twice: `gitleaks dir` on the working tree and `gitleaks git` on the full commit history. A
secret deleted in a later commit still lives in history, so the history pass matters most. Secrets
are redacted (`--redact`) before they reach the report. A finding on a git-ignored file is dropped
to `low` (it was never committed), and a finding in history is `high` with the commit and advice to
rotate first.

### sca — osv-scanner (+ OSV.dev for Gradle)
`osv-scanner` reads every lockfile it recognizes (`package-lock.json`, `pubspec.lock`, pip, Gradle
lockfiles) and asks OSV.dev which packages have known advisories. Android projects usually have no
Gradle lockfile, so the suite also parses `gradle/libs.versions.toml`, resolves `version.ref`
entries, and queries OSV.dev's Maven ecosystem directly. Advisories grouped by OSV (a GHSA and its
CVE) collapse to one finding; severity follows the advisory's CVSS.

### sast — semgrep
Community rulesets are chosen per app kind (`p/python`, `p/kotlin`, `p/android`, `p/typescript`,
`p/dart`, …) plus `p/security-audit`, `p/owasp-top-ten`, `p/secrets`, and this repo's own rules in
`rules/semgrep/`. `--metrics=off` so nothing is uploaded. Low-confidence audit rules are dropped one
severity step to keep the top of the report trustworthy.

### iac — trivy
`trivy fs --scanners misconfig` over the tree for Dockerfile, Terraform, Kubernetes, Helm and
CloudFormation misconfigurations. Build and dependency directories are skipped.

## Built-in analyzers

### firebase-rules
Parses Firestore/Storage rules into (path, operations, condition) triples, tracking nested `match`
blocks so the full document path is known, and skips `function` bodies. It flags:
- `allow … : if true` or no condition → **open to the internet** (critical for writes).
- `if request.auth != null` as the only check → **any signed-in account**; with recursive
  wildcards or `list`, that means enumerating everyone's data.
- test-mode rules (`request.time < timestamp.date(...)`).
- writes with no `request.resource` / `keys().hasOnly()` validation.
- RTDB `.read`/`.write` of `true` or `auth != null`.
- a Firebase SDK in the app but **no rules file in the repo** (so rules live only in the console,
  unreviewable).

It is deliberately tuned not to flag correctly owner-scoped rules — there is a regression test
(`test_phoniq_real_rules_are_clean`) that runs it against PhonIQ's real, tight rules and asserts
zero serious findings.

### firebase-config
Reads `firebase.json` Hosting headers (CSP, `X-Content-Type-Options`, `Referrer-Policy`,
clickjacking, `unsafe-inline`/`unsafe-eval` in CSP) for the catch-all `**` source, and parses
Cloud Functions source for `onCall`/`onRequest` exports: callables that never read `request.auth`,
missing App Check, `cors: true`/`*`, public HTTP functions, and functions with no `maxInstances`
cap (a cost-DoS risk).

### android
Parses every `AndroidManifest.xml` under `src/` (XML, namespace-aware): `debuggable`, `allowBackup`
without extraction rules, app-wide cleartext, and **exported** activities/services/receivers/
providers that have no permission (launcher activities are excluded by design). It follows
`networkSecurityConfig` to flag user-CA trust and cleartext domains, and parses release
`buildTypes` for minify-off, debuggable releases, hardcoded signing passwords (literal strings
only — values read from `keystore.properties` are the correct pattern and are not flagged), and old
`targetSdk`.

### llm-static
The AI-specific surface:
- **Hidden Unicode** — bidi controls (Trojan Source) and Unicode tag characters (ASCII smuggling)
  everywhere; other zero-width characters in code. ZWJ/ZWNJ (U+200C/200D) are **not** flagged
  because they are legitimate in Indic scripts and emoji, and localized string resources are
  skipped for the low-severity zero-width check.
- **Prompt-injection phrasing** in the files agents actually read (`CLAUDE.md`, `AGENTS.md`,
  skills, prompts) — "ignore previous instructions", "do not tell the user", fake `<system>` tags.
- **MCP** — tool descriptions carrying injection text, committed MCP client configs with a real
  token (env-var references are fine), and plain-HTTP non-loopback MCP URLs.

All of these run only over git-tracked files, so nested worktrees, build output and local-only
copies never pollute the report.

## Why static-only

These are the owner's own production apps. Running a DAST crawler or an MCP fuzzer against a live
instance risks corrupting real data, tripping abuse limits, or racking up a bill, so the suite
stays to static analysis and config review, which is safe to run on every commit. Dynamic testing,
if ever added, belongs against a disposable local instance with explicit opt-in — never the
defaults here.
