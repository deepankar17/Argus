"""TLS / HTTPS configuration of a running host, with sslyze. Read-only: it negotiates handshakes
and reads the certificate and supported protocols; it sends no application traffic and is safe
against production."""
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from ..core import Finding
from .core import Target, authorize
from .shared import run_tool, tool_available

NAME = "tls"
CATEGORY = "TLS / transport"


def _hostport(url):
    s = urlsplit(url if "//" in url else "//" + url)
    return s.hostname, s.port or 443


def scan(target: Target, intrusive: bool = False, allow_prod_active: bool = False):
    # TLS inspection is read-only, so it is never treated as intrusive.
    authorize(target, intrusive=False, allow_prod_active=allow_prod_active)
    if not tool_available("sslyze") and not _py_sslyze():
        return [Finding(NAME, "tool-missing", "info", "sslyze not installed (pip install sslyze)",
                        target.url, category=CATEGORY, app=target.app)]
    host, port = _hostport(target.url)
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "sslyze.json"
        run_tool(["python3", "-m", "sslyze", "--json_out", str(out), "%s:%d" % (host, port)],
                 timeout=600, ok_codes=range(0, 256))
        data = json.loads(out.read_text()) if out.exists() else {}
    for res in data.get("server_scan_results", []):
        r = res.get("scan_result", {})
        weak = []
        for proto, key in (("SSL 2.0", "ssl_2_0_cipher_suites"), ("SSL 3.0", "ssl_3_0_cipher_suites"),
                           ("TLS 1.0", "tls_1_0_cipher_suites"), ("TLS 1.1", "tls_1_1_cipher_suites")):
            accepted = (((r.get(key) or {}).get("result") or {}).get("accepted_cipher_suites")) or []
            if accepted:
                weak.append(proto)
        if weak:
            findings.append(Finding(NAME, "weak-protocol", "medium", "%s still enabled on %s" % (", ".join(weak), host),
                                    target.url, category=CATEGORY, app=target.app,
                                    fix="Disable SSLv2/v3 and TLS 1.0/1.1; serve TLS 1.2+ only."))
        certinfo = ((r.get("certificate_info") or {}).get("result") or {})
        for dep in certinfo.get("certificate_deployments", []):
            if dep.get("leaf_certificate_subject_matches_hostname") is False:
                findings.append(Finding(NAME, "cert-hostname", "high", "Certificate does not match %s" % host,
                                        target.url, category=CATEGORY, app=target.app))
            trust = dep.get("path_validation_results", [])
            if any(not p.get("was_validation_successful", True) for p in trust):
                findings.append(Finding(NAME, "cert-untrusted", "high", "Certificate chain failed validation on %s" % host,
                                        target.url, category=CATEGORY, app=target.app,
                                        fix="Serve the full chain; renew if expired."))
    if not findings:
        findings.append(Finding(NAME, "tls-ok", "info", "No TLS protocol/cert problems found on %s" % host,
                                target.url, category=CATEGORY, app=target.app))
    return findings


def _py_sslyze():
    try:
        import sslyze  # noqa: F401
        return True
    except ImportError:
        return False
