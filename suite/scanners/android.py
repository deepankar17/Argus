"""Android app config: every AndroidManifest.xml, network security config and Gradle build file in
the project (native Kotlin apps and the android/ folder of Flutter apps). Static; MobSF (the
mobsf scanner) covers the built APK."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core import Finding, line_of, tracked_set

NAME = "android"
CATEGORY = "Android"
A = "{http://schemas.android.com/apk/res/android}"
SKIP = re.compile(r"/(build|\.gradle|node_modules|intermediates|generated|\.cxx|\.kotlin)/|"
                  r"/\.claude/|/worktrees/|/\.git/")
SENSITIVE_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_CONTACTS", "WRITE_CONTACTS",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "PROCESS_OUTGOING_CALLS", "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW", "MANAGE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
    "REQUEST_INSTALL_PACKAGES", "BIND_NOTIFICATION_LISTENER_SERVICE", "READ_MEDIA_IMAGES", "READ_MEDIA_AUDIO",
    "BODY_SENSORS", "USE_FULL_SCREEN_INTENT",
}


def _line(text, needle):
    i = text.find(needle)
    return line_of(text, i) if i >= 0 else 0


def _is_launcher(el):
    for f in el.findall("intent-filter"):
        actions = {a.get(A + "name") for a in f.findall("action")}
        cats = {c.get(A + "name") for c in f.findall("category")}
        if "android.intent.action.MAIN" in actions and ("android.intent.category.LAUNCHER" in cats or
                                                        "android.intent.category.LEANBACK_LAUNCHER" in cats):
            return True
    return False


def check_manifest(text, source, res_dir=None):
    findings = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [Finding(NAME, "manifest-parse", "info", "Could not parse %s" % source, source, detail=str(e),
                        category=CATEGORY)]
    app = root.find("application")
    if app is not None:
        if app.get(A + "debuggable") == "true":
            findings.append(Finding(NAME, "debuggable", "high", "android:debuggable=\"true\" in the manifest", source,
                                    _line(text, "debuggable"), category=CATEGORY,
                                    detail="A debuggable release lets anyone with the phone attach a debugger and read app data.",
                                    fix="Remove it; Gradle sets it for debug builds only."))
        backup = app.get(A + "allowBackup")
        if backup == "true" and not (app.get(A + "dataExtractionRules") or app.get(A + "fullBackupContent")):
            findings.append(Finding(NAME, "allow-backup", "medium", "App data is backed up with no exclusion rules",
                                    source, _line(text, "allowBackup"), category=CATEGORY,
                                    detail="allowBackup=\"true\" with no dataExtractionRules: tokens and databases go to "
                                           "cloud backup and adb backup.",
                                    fix="Set allowBackup=\"false\" or add dataExtractionRules that exclude secrets."))
        if app.get(A + "usesCleartextTraffic") == "true":
            findings.append(Finding(NAME, "cleartext", "medium", "Cleartext HTTP is allowed app-wide", source,
                                    _line(text, "usesCleartextTraffic"), category=CATEGORY,
                                    fix="Remove usesCleartextTraffic or limit cleartext to specific debug hosts in a "
                                        "network security config."))
        nsc = app.get(A + "networkSecurityConfig")
        if nsc and res_dir is not None:
            p = Path(res_dir) / "xml" / (nsc.split("/")[-1] + ".xml")
            if p.exists():
                findings += check_network_config(p.read_text(errors="replace"), str(source).rsplit("/", 1)[0]
                                                 + "/res/xml/" + p.name)
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.findall(tag):
                name = el.get(A + "name", "?")
                exported = el.get(A + "exported")
                if exported is None and tag == "provider":
                    continue  # providers default to not exported since API 17
                if exported != "true":
                    continue
                perm = el.get(A + "permission") or (el.get(A + "readPermission") if tag == "provider" else None)
                if perm or (tag in ("activity", "activity-alias") and _is_launcher(el)):
                    continue
                if tag == "provider":
                    sev, why = "high", "Any app on the phone can query it."
                elif tag in ("service", "receiver"):
                    sev, why = "medium", "Any app can start or send to it; check it validates who calls and what it gets."
                else:
                    sev, why = "low", "Any app can open it with any extras; check it handles untrusted intents."
                findings.append(Finding(NAME, "exported-" + tag, sev, "Exported %s %s has no permission" % (tag, name),
                                        source, _line(text, name.split(".")[-1]), category=CATEGORY, detail=why,
                                        fix="Set exported=\"false\" if only this app uses it, or protect it with a "
                                            "signature permission."))
    perms = sorted({p.get(A + "name", "").split(".")[-1] for p in root.findall("uses-permission")} & SENSITIVE_PERMS)
    if perms:
        findings.append(Finding(NAME, "sensitive-permissions", "info", "Sensitive permissions: " + ", ".join(perms),
                                source, category=CATEGORY,
                                detail="Not a bug. Each one needs a Play declaration and should be used only for the "
                                       "feature that asks for it.",
                                fix="Drop any the app no longer needs."))
    return findings


def check_network_config(text, source):
    findings = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return findings
    for cfg in [root.find("base-config")] + root.findall("domain-config"):
        if cfg is None:
            continue
        where = "base-config" if cfg.tag == "base-config" else "domain " + ", ".join(
            d.text or "" for d in cfg.findall("domain"))
        if cfg.get("cleartextTrafficPermitted") == "true":
            findings.append(Finding(NAME, "nsc-cleartext", "medium" if cfg.tag == "base-config" else "low",
                                    "Network config allows cleartext for %s" % where, source,
                                    _line(text, "cleartextTrafficPermitted"), category=CATEGORY,
                                    fix="Use HTTPS; keep cleartext only for local debug hosts in debug-overrides."))
        for c in cfg.iter("certificates"):
            if c.get("src") == "user":
                findings.append(Finding(NAME, "nsc-user-ca", "high", "Release builds trust user-installed CAs (%s)" % where,
                                        source, _line(text, 'src="user"'), category=CATEGORY,
                                        detail="Anyone who can install a CA on the phone can read the app's TLS traffic.",
                                        fix="Move user CAs into <debug-overrides>."))
    return findings


def check_gradle(text, source):
    findings = []
    release = re.search(r"(?:getByName\(\"release\"\)|release)\s*\{", text)
    if release:
        depth, i = 1, release.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        block = text[release.end():i]
        if re.search(r"(isMinifyEnabled|minifyEnabled)\s*=?\s*false", block):
            findings.append(Finding(NAME, "release-no-minify", "medium", "Release build is not minified/obfuscated",
                                    source, line_of(text, release.start()), category=CATEGORY,
                                    detail="R8 off: code is trivially readable and unused code (and its bugs) ships.",
                                    fix="isMinifyEnabled = true and isShrinkResources = true for release."))
        if re.search(r"(isDebuggable|debuggable)\s*=?\s*true", block):
            findings.append(Finding(NAME, "release-debuggable", "high", "Release build is debuggable", source,
                                    line_of(text, release.start()), category=CATEGORY, fix="Remove debuggable from release."))
    # Only a direct string literal assignment, e.g. storePassword = "hunter2". A value read from a
    # properties file (storePassword = props.getProperty("storePassword")) is the correct pattern.
    for m in re.finditer(r"(?m)^\s*(storePassword|keyPassword)\s*=\s*\"([^\"$\n]+)\"", text):
        findings.append(Finding(NAME, "hardcoded-signing-password", "high", "Signing %s is written in %s" % (m.group(1), source),
                                source, line_of(text, m.start()), category=CATEGORY,
                                fix="Read it from keystore.properties (git-ignored) or an environment variable."))
    m = re.search(r"targetSdk(?:Version)?\s*=?\s*(\d+)", text)
    if m and int(m.group(1)) < 34:
        findings.append(Finding(NAME, "old-target-sdk", "low", "targetSdk %s is below 34" % m.group(1), source,
                                line_of(text, m.start()), category=CATEGORY,
                                fix="Raise targetSdk; Play requires recent levels and newer ones close old loopholes."))
    return findings


def scan(app):
    findings = []
    tracked = tracked_set(app.path)

    def included(path):
        source = str(path.relative_to(app.path))
        if SKIP.search("/" + source):
            return None
        if tracked is not None and source not in tracked:
            return None  # untracked scratch: a nested worktree, a local copy, generated output
        return source

    for mf in app.path.rglob("AndroidManifest.xml"):
        source = included(mf)
        if source and "/src/" in source:
            findings += check_manifest(mf.read_text(errors="replace"), source, mf.parent / "res")
    for g in list(app.path.rglob("build.gradle.kts")) + list(app.path.rglob("build.gradle")):
        source = included(g)
        if source:
            findings += check_gradle(g.read_text(errors="replace"), source)
    return findings
