"""Firebase project config: Hosting security headers in firebase.json, and Cloud Functions
endpoints (public HTTP functions, callables that never check auth, App Check, CORS)."""
import json
import re

from ..core import Finding, line_of

NAME = "firebase-config"
CATEGORY = "Firebase config"

WANTED_HEADERS = {
    "content-security-policy": ("medium", "No Content-Security-Policy", "Limits what scripts can run if an XSS slips in."),
    "x-content-type-options": ("low", "No X-Content-Type-Options: nosniff", "Stops MIME sniffing of uploads and responses."),
    "referrer-policy": ("low", "No Referrer-Policy", "Keeps full URLs (and anything in them) out of other sites' logs."),
}


def _hosting_headers(hosting):
    """Header names (lower case) set for every path (source "**")."""
    names, csp = set(), ""
    for h in hosting.get("headers", []) or []:
        if h.get("source") in ("**", "**/*", "/**"):
            for kv in h.get("headers", []):
                names.add(kv.get("key", "").lower())
                if kv.get("key", "").lower() == "content-security-policy":
                    csp = kv.get("value", "")
    return names, csp


def check_hosting(conf, source):
    findings = []
    hostings = conf.get("hosting")
    for hosting in (hostings if isinstance(hostings, list) else [hostings] if hostings else []):
        site = hosting.get("site") or hosting.get("target") or "default site"
        names, csp = _hosting_headers(hosting)
        for header, (sev, title, why) in WANTED_HEADERS.items():
            if header not in names:
                findings.append(Finding(NAME, "hosting-" + header, sev, "%s on %s" % (title, site), source,
                                        category=CATEGORY, detail=why,
                                        fix="Add it under hosting.headers for source \"**\" in firebase.json."))
        if "x-frame-options" not in names and "frame-ancestors" not in csp:
            findings.append(Finding(NAME, "hosting-clickjacking", "low", "Pages on %s can be framed" % site, source,
                                    category=CATEGORY, detail="Neither X-Frame-Options nor CSP frame-ancestors is set.",
                                    fix="Set X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
        script_src = re.search(r"script-src([^;]*)", csp)
        directive = script_src.group(1) if script_src else (re.search(r"default-src([^;]*)", csp) or [None, ""])[1] or ""
        if "'unsafe-inline'" in directive and "'nonce-" not in directive and "'strict-dynamic'" not in directive:
            findings.append(Finding(NAME, "csp-unsafe-inline", "medium", "CSP allows inline scripts on %s" % site,
                                    source, category=CATEGORY, detail="'unsafe-inline' in script-src defeats most of CSP's XSS protection.",
                                    fix="Use hashes (as for other inline scripts) or move scripts to files."))
        if "'unsafe-eval'" in directive:
            findings.append(Finding(NAME, "csp-unsafe-eval", "medium", "CSP allows eval on %s" % site, source,
                                    category=CATEGORY, fix="Remove 'unsafe-eval' from script-src."))
    return findings


EXPORT = re.compile(r"export\s+const\s+(\w+)\s*=\s*(onRequest|onCall)\s*\(", re.M)
LEGACY = re.compile(r"(?:exports|export\s+const)\.?\s*(\w+)\s*=\s*functions(?:\.\w+\([^)]*\))*\.https\.(onRequest|onCall)\(")


def _call_args(text, start):
    """The text of a call's arguments from the opening parenthesis at start."""
    depth, i = 0, start
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return text[start + 1:]


def check_functions_source(text, source):
    findings = []
    for m in list(EXPORT.finditer(text)) + list(LEGACY.finditer(text)):
        name, kind = m.group(1), m.group(2)
        args = _call_args(text, m.end() - 1)
        line = line_of(text, m.start())
        # Options passed by name (const chatCall = {...}) are looked up in the same file.
        opts_name = re.match(r"\s*(\w+)\s*,", args)
        opts = args.split("=>", 1)[0]
        if opts_name:
            d = re.search(r"const\s+%s\s*(?::[^=]+)?=\s*(\{[^;]*\})" % re.escape(opts_name.group(1)), text)
            opts += d.group(1) if d else ""
        if kind == "onCall":
            if not re.search(r"\.auth\b|context\.auth|request\.auth", args):
                findings.append(Finding(
                    NAME, "callable-no-auth", "high", "Callable %s never checks the caller's auth" % name, source,
                    line, category=CATEGORY,
                    detail="Callable functions are reachable by anyone with the project id. Without a check on "
                           "request.auth they run for unauthenticated callers.",
                    fix="Throw HttpsError('unauthenticated') when request.auth is missing."))
            if "enforceAppCheck" not in opts:
                findings.append(Finding(
                    NAME, "callable-no-appcheck", "low", "Callable %s does not enforce App Check" % name, source, line,
                    category=CATEGORY, detail="Scripts can call it directly with a valid user token, bypassing the app.",
                    fix="Set enforceAppCheck: true once App Check is set up (debug tokens for debug builds)."))
        else:
            public = 'invoker: "public"' in opts or "invoker: 'public'" in opts or "invoker" not in opts
            checks_auth = re.search(r"authorization|verifyIdToken|getAuth\(\)|x-api-key|timingSafeEqual", args, re.I)
            if public and not checks_auth:
                findings.append(Finding(
                    NAME, "public-http-function", "info", "HTTP function %s is public with no auth check" % name,
                    source, line, category=CATEGORY,
                    detail="Fine for a deliberately public endpoint; make sure it limits input size, rate and "
                           "origins, and has maxInstances set so abuse cannot run up a bill.",
                    fix="Add maxInstances and input limits; check an ID token if it is not meant to be public."))
            if "maxInstances" not in opts:
                findings.append(Finding(NAME, "no-max-instances", "low", "HTTP function %s has no maxInstances" % name,
                                        source, line, category=CATEGORY,
                                        fix="Set maxInstances so a flood cannot scale it (and the bill) without bound."))
        if re.search(r"cors\s*:\s*true|cors\(\s*\{\s*origin\s*:\s*(true|['\"]\*['\"])", args + opts):
            findings.append(Finding(NAME, "cors-any-origin", "medium", "%s allows any origin (CORS)" % name, source,
                                    line, category=CATEGORY, fix="List the allowed origins."))
    return findings


def scan(app):
    findings = []
    fb = app.path / "firebase.json"
    if fb.exists():
        try:
            findings += check_hosting(json.loads(fb.read_text()), "firebase.json")
        except ValueError:
            pass
    for src in list(app.path.glob("functions/src/**/*.ts")) + list(app.path.glob("functions/**/*.js")):
        if re.search(r"node_modules|/lib/|\.test\.|/build/", str(src)):
            continue
        findings += check_functions_source(src.read_text(errors="replace"), str(src.relative_to(app.path)))
    return findings
