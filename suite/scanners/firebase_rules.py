"""Firebase security rules: Firestore, Cloud Storage and Realtime Database. Reads the rules files
the project deploys and flags rules that let anyone (or any signed-in account) read or write more
than their own data. Purely static; nothing is sent to Firebase."""
import json
import re
from pathlib import Path

from ..core import Finding, line_of

NAME = "firebase-rules"
CATEGORY = "Firebase rules"

OPEN = re.compile(r"^\s*(true|)\s*$")
TEST_MODE = re.compile(r"request\.time\s*<\s*timestamp\.date\(")
AUTH_ONLY = re.compile(r"^\s*\(?\s*request\.auth\s*!=\s*null\s*\)?\s*$")
OWNER = re.compile(r"request\.auth\.uid\s*==|==\s*request\.auth\.uid|request\.auth\.token")
WRITE_OPS = {"write", "create", "update", "delete"}


def _strip_comments(text):
    # Keep offsets (and so line numbers) by blanking comments instead of removing them.
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"/\*.*?\*/", blank, text, flags=re.S)
    return re.sub(r"//[^\n]*", blank, text)


def parse_rules(text):
    """Yield (match_path, ops, condition, line) for every allow statement, with the full nested path."""
    text = _strip_comments(text)
    stack, pending, i, out = [], None, 0, []
    token = re.compile(r"match\s+(/[^\s{]*)\s*\{|function\s+\w+\s*\([^)]*\)\s*\{|allow\s+([\w,\s]+?)\s*(?::\s*if\s+|;)|\{|\}")
    while True:
        m = token.search(text, i)
        if not m:
            break
        s = m.group(0)
        if s.startswith("match"):
            stack.append(m.group(1))
            i = m.end()
        elif s.startswith("function"):
            # Skip the function body.
            depth, j = 1, m.end()
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            i = j
        elif s.startswith("allow"):
            ops = {o.strip() for o in m.group(2).split(",") if o.strip()}
            if s.rstrip().endswith(";"):
                cond, end = "", m.end()
            else:
                end = text.find(";", m.end())
                end = len(text) if end < 0 else end
                cond = " ".join(text[m.end():end].split())
            out.append(("".join(stack) or "/", ops, cond, line_of(text, m.start())))
            i = end + 1
        elif s == "{":
            stack.append("")
            i = m.end()
        else:
            if stack:
                stack.pop()
            i = m.end()
    return out


def _user_scoped(path, cond):
    """Is access tied to the caller's own uid (a {uid} in the path compared with request.auth.uid,
    or a field check against it)?"""
    return bool(OWNER.search(cond))


def check_rules_text(text, source, kind):
    findings = []
    if kind == "firestore" and not re.search(r"rules_version\s*=\s*['\"]2['\"]", text):
        findings.append(Finding(NAME, "rules-version", "low", "%s rules do not set rules_version = '2'" % source,
                                source, 1, category=CATEGORY,
                                detail="Version 1 rules treat recursive wildcards differently and lack newer functions.",
                                fix="Start the file with rules_version = '2';"))
    for path, ops, cond, line in parse_rules(text):
        writes = ops & WRITE_OPS
        reads = ops & {"read", "get", "list"}
        what = ", ".join(sorted(ops))
        recursive = "=**}" in path
        if cond.strip() == "false":
            continue
        if OPEN.match(cond):
            sev = "critical" if writes else "high"
            findings.append(Finding(
                NAME, "open-access", sev, "Anyone on the internet can %s %s" % (what, path), source, line,
                category=CATEGORY,
                detail="allow %s with no condition (or if true) in %s. No sign-in is needed." % (what, kind),
                fix="Require request.auth and tie access to the caller, e.g. request.auth.uid == userId."))
            continue
        if TEST_MODE.search(cond):
            findings.append(Finding(
                NAME, "test-mode", "high", "Test-mode rule (open until a date) on %s" % path, source, line,
                category=CATEGORY, detail="Condition: %s" % cond[:200],
                fix="Replace the time-based rule with real access rules before the date passes or ships."))
            continue
        if AUTH_ONLY.match(cond):
            if writes:
                findings.append(Finding(
                    NAME, "any-user-write", "high" if recursive else "medium",
                    "Any signed-in account can %s %s" % (", ".join(sorted(writes)), path), source, line,
                    category=CATEGORY,
                    detail="The only check is request.auth != null. With anonymous or open sign-up, that is anyone.",
                    fix="Check ownership (request.auth.uid) and validate the fields written."))
            if reads:
                findings.append(Finding(
                    NAME, "any-user-read", "medium" if recursive or "list" in ops or "read" in ops else "low",
                    "Any signed-in account can %s every document under %s" % ("/".join(sorted(reads)), path),
                    source, line, category=CATEGORY,
                    detail="read includes list, so a client can enumerate the whole collection.",
                    fix="If the data is not meant to be public to all users, scope it to the owner; allow get "
                        "but not list when only lookups by id are needed."))
            continue
        if recursive and not _user_scoped(path, cond):
            findings.append(Finding(
                NAME, "recursive-wildcard", "medium", "Recursive wildcard %s grants %s" % (path, what), source,
                line, category=CATEGORY, detail="Condition: %s" % cond[:200],
                fix="Avoid {document=**} grants; they cover every subcollection, including future ones."))
        if ({"create", "write", "update"} & ops) and kind == "firestore" and "keys()" not in cond \
                and "request.resource" not in cond:
            findings.append(Finding(
                NAME, "no-schema", "low", "Writes to %s are not validated" % path, source, line,
                category=CATEGORY, detail="The rule checks who writes but not what (no request.resource checks).",
                fix="Limit fields with request.resource.data.keys().hasOnly([...]) and check types and sizes."))
    return findings


def check_rtdb(data, source, path="/"):
    findings = []
    if not isinstance(data, dict):
        return findings
    for key, value in data.items():
        if key in (".read", ".write"):
            cond = str(value).strip()
            op = "write" if key == ".write" else "read"
            if cond.lower() == "true":
                findings.append(Finding(NAME, "rtdb-open", "critical" if op == "write" else "high",
                                        "Anyone can %s Realtime Database %s" % (op, path), source, 0,
                                        category=CATEGORY, fix="Require auth and scope to auth.uid."))
            elif re.fullmatch(r"\(?\s*auth\s*!==?\s*null\s*\)?", cond):
                findings.append(Finding(NAME, "rtdb-any-user", "medium",
                                        "Any signed-in account can %s Realtime Database %s" % (op, path), source, 0,
                                        category=CATEGORY, fix="Scope to auth.uid."))
        elif isinstance(value, dict) and not key.startswith("."):
            findings += check_rtdb(value, source, path.rstrip("/") + "/" + key)
    return findings


def _uses_firebase_service(app, words):
    for name in ("pubspec.yaml", "package.json", "app/build.gradle.kts", "android/app/build.gradle.kts",
                 "android/app/build.gradle", "functions/package.json"):
        p = app.path / name
        if p.exists() and any(w in p.read_text(errors="replace") for w in words):
            return True
    return False


def scan(app):
    findings, seen = [], set()
    fb = app.path / "firebase.json"
    conf = {}
    if fb.exists():
        try:
            conf = json.loads(fb.read_text())
        except ValueError:
            conf = {}
    declared = []
    for svc, kind in (("firestore", "firestore"), ("storage", "storage"), ("database", "rtdb")):
        entry = conf.get(svc)
        for e in (entry if isinstance(entry, list) else [entry] if entry else []):
            if isinstance(e, dict) and e.get("rules"):
                declared.append((app.path / e["rules"], kind))
    for p in list(app.path.glob("*.rules")) + list(app.path.glob("firebase/*.rules")):
        kind = "storage" if "storage" in p.name else "firestore"
        declared.append((p, kind))
    for path, kind in declared:
        if path in seen or not path.exists():
            continue
        seen.add(path)
        source = str(path.relative_to(app.path))
        if kind == "rtdb":
            try:
                data = json.loads(re.sub(r"//[^\n]*", "", path.read_text()))
                findings += check_rtdb(data.get("rules", data), source)
            except ValueError as e:
                findings.append(Finding(NAME, "rtdb-parse", "info", "Could not parse %s" % source, source,
                                        detail=str(e), category=CATEGORY))
        else:
            findings += check_rules_text(path.read_text(errors="replace"), source, kind)
    kinds = {k for _, k in declared}
    for kind, words in (("firestore", ["cloud_firestore", "firebase-firestore", "firestore"]),
                        ("storage", ["firebase_storage", "firebase-storage"]),
                        ("rtdb", ["firebase_database", "firebase-database"])):
        if kind not in kinds and _uses_firebase_service(app, words):
            findings.append(Finding(
                NAME, "rules-not-in-repo", "medium", "The app uses %s but its rules are not in the repo" % kind,
                "firebase.json", 0, category=CATEGORY,
                detail="Rules edited only in the console cannot be reviewed, tested or rolled back, and may "
                       "still be the open test-mode rules.",
                fix="firebase init %s, commit the rules file, and deploy from the repo."
                    % {"rtdb": "database"}.get(kind, kind)))
    return findings
