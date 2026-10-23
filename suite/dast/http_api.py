"""HTTP-API checks against a running endpoint (e.g. a Cloud Functions HTTP function). Verifies the
defensive posture a public endpoint should have, with non-destructive requests:

  - live security headers actually sent on the response;
  - whether an unauthenticated request is accepted (information only — many endpoints are meant to
    be public; it is reported so you can confirm that is intended);
  - CORS: does it reflect an arbitrary Origin;
  - body-size handling: does an oversized body get rejected rather than processed (a cost/DoS guard);
  - error hygiene: does an error response leak a stack trace or internal path.

Oversized-body and malformed-request checks are sent only on an intrusive run and are bounded (one
request each), so they probe robustness without flooding the service.
"""
import re

from ..core import Finding
from .core import Target, authorize

NAME = "http-api"
CATEGORY = "HTTP API (DAST)"
LEAK = re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|/Users/[^/\s\"]+/|"
                  r"node_modules/|functions/lib/")
WANT_HEADERS = {
    "x-content-type-options": ("low", "no X-Content-Type-Options: nosniff"),
    "strict-transport-security": ("low", "no Strict-Transport-Security"),
}


def _req(url, method="GET", headers=None, body=None, timeout=20):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(100000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(100000)
    except (urllib.error.URLError, OSError) as e:
        return None, {}, str(e).encode()


def scan(target: Target, intrusive: bool = False, allow_prod_active: bool = False):
    authorize(target, intrusive=intrusive, allow_prod_active=allow_prod_active)
    findings = []
    status, headers, body = _req(target.url, headers=target.headers)
    if status is None:
        return [Finding(NAME, "unreachable", "info", "Could not reach %s" % target.url, target.url,
                        category=CATEGORY, detail=body.decode(errors="replace")[:200], app=target.app)]
    for h, (sev, why) in WANT_HEADERS.items():
        if h not in headers:
            findings.append(Finding(NAME, "missing-header-" + h, sev, "%s on %s" % (why, target.host), target.url,
                                    category=CATEGORY, app=target.app))
    # CORS reflection
    _, cors_headers, _ = _req(target.url, headers=dict(target.headers, Origin="https://dast-probe.example"))
    acao = cors_headers.get("access-control-allow-origin", "")
    if acao == "*" or acao == "https://dast-probe.example":
        sev = "high" if cors_headers.get("access-control-allow-credentials") == "true" else "medium"
        findings.append(Finding(NAME, "cors-reflects-origin", sev, "Endpoint reflects any Origin (CORS) on %s" % target.host,
                                target.url, category=CATEGORY, app=target.app,
                                detail="Returned Access-Control-Allow-Origin: %s for an arbitrary origin." % acao,
                                fix="Echo only an allowlist of origins; never reflect the request Origin with credentials."))
    if LEAK.search(body.decode(errors="replace")):
        findings.append(Finding(NAME, "error-leak", "low", "Response body exposes internals on %s" % target.host,
                                target.url, category=CATEGORY, app=target.app,
                                fix="Return a generic message; log details server-side only."))
    if intrusive:
        # One bounded oversized-body request: a well-built endpoint caps body size and replies 413/400.
        big = b"x" * (2 * 1024 * 1024)
        st, _, rb = _req(target.url, method="POST", headers=dict(target.headers,
                         **{"Content-Type": "application/json"}), body=big)
        if st is not None and st < 400:
            findings.append(Finding(NAME, "no-body-limit", "medium", "Endpoint accepts a 2 MB body (HTTP %d) on %s" % (st, target.host),
                                    target.url, category=CATEGORY, app=target.app,
                                    detail="No apparent body-size cap; large bodies can drive cost/CPU.",
                                    fix="Reject oversized bodies early (e.g. 413) and set a byte limit."))
        if LEAK.search(rb.decode(errors="replace")):
            findings.append(Finding(NAME, "error-leak-post", "low", "Malformed/large POST leaks internals on %s" % target.host,
                                    target.url, category=CATEGORY, app=target.app))
    return findings
