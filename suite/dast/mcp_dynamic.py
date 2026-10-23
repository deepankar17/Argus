"""MCP server resilience / posture checks against a running MCP endpoint.

This verifies the security properties an MCP server should have — the same ones CrewChat documents
for itself (loopback-only, token required, same-origin writes, bounded bodies, graceful errors). It
is a defensive posture check, not an exploitation tool: it sends a handful of well-formed and one
malformed request and reads the responses. It does not fuzz with injection/traversal payloads, does
not brute-force, and should be pointed at a local throwaway instance (env "local") — start one with
its own CREWCHAT_HOME and a spare port, the way the project's own e2e harness does.

Checks:
  - auth-required:   a request with no token is rejected (not 2xx).
  - loopback-bind:   the endpoint is not reachable on a non-loopback interface.
  - same-origin:     a cross-site Origin on a browser-style request is rejected.
  - body-limit:      an oversized body is rejected rather than processed.
  - error-hygiene:   a malformed JSON-RPC body yields a clean error, not a stack trace.
"""
import http.client
import socket
from urllib.parse import urlsplit

from ..core import Finding
from .core import Target, authorize

NAME = "mcp-dynamic"
CATEGORY = "MCP (DAST)"
LEAK = ("Traceback (most recent call last)", 'File "/', "  at ", "/Users/")


def _conn(host, port, timeout=15):
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _send(url, body=b"", headers=None, method="POST", host_override=None, timeout=15):
    s = urlsplit(url)
    host, port, path = s.hostname, s.port or 80, s.path or "/"
    conn = _conn(host_override or host, port, timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read(500000).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException) as e:
        return None, str(e)
    finally:
        conn.close()


def _lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip if not ip.startswith("127.") else None
    except OSError:
        return None


def scan(target: Target, intrusive: bool = False, allow_prod_active: bool = False):
    authorize(target, intrusive=intrusive, allow_prod_active=allow_prod_active)
    findings = []
    s = urlsplit(target.url)
    host, port, path = s.hostname, s.port or 80, s.path or "/mcp"
    ct = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    init = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

    # auth-required: no Authorization header
    st, _ = _send(target.url, init, ct)
    auth_required = not (st is not None and st < 400)
    if not auth_required:
        findings.append(Finding(NAME, "mcp-no-auth", "critical", "MCP endpoint answers without a token (HTTP %d)" % st,
                                target.url, category=CATEGORY, app=target.app,
                                fix="Require a bearer token on every MCP request."))

    auth = dict(ct, Authorization="Bearer %s" % target.token) if target.token else ct

    # loopback-bind: try the LAN IP; a loopback-only server refuses the connection.
    lan = _lan_ip()
    if lan and host in ("127.0.0.1", "localhost", "::1"):
        st, _ = _send("http://%s:%d%s" % (lan, port, path), init, auth, timeout=4)
        if st is not None:
            findings.append(Finding(NAME, "mcp-bind-all", "high", "MCP server is reachable on a non-loopback address (%s)" % lan,
                                    target.url, category=CATEGORY, app=target.app,
                                    detail="A local MCP server should bind 127.0.0.1 and be reached over a private "
                                           "network (e.g. a VPN), not exposed on the LAN.",
                                    fix="Bind 127.0.0.1 only."))

    # DNS-rebinding / cross-origin: the real risk is a malicious web page reaching the loopback
    # server from the victim's browser. That only works if the server answers WITHOUT the token
    # (a browser cannot attach a secret bearer token cross-origin). So this is only a finding when a
    # cross-origin request with NO token is accepted; a token-authenticated endpoint is not at risk.
    if not auth_required:
        st, _ = _send(target.url, init, dict(ct, Origin="https://evil.example", Host="%s:%d" % (host, port)))
        if st is not None and st < 400:
            findings.append(Finding(NAME, "mcp-origin", "high", "MCP endpoint accepts an unauthenticated cross-site request",
                                    target.url, category=CATEGORY, app=target.app,
                                    detail="A browser request from another site, with no token, was accepted "
                                           "(DNS-rebinding risk for a loopback server).",
                                    fix="Require a token and reject requests whose Origin is not the server's own."))

    if intrusive:
        # body-limit: one bounded oversized body
        st, _ = _send(target.url, b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":"' + b"x" * (1024 * 1024) + b'"}', auth)
        if st is not None and st < 400:
            findings.append(Finding(NAME, "mcp-no-body-limit", "medium", "MCP endpoint accepts a 1 MB request body",
                                    target.url, category=CATEGORY, app=target.app,
                                    fix="Cap request body size and reject oversized requests."))
        # error-hygiene: malformed JSON
        st, text = _send(target.url, b'{not json', auth)
        if any(m in text for m in LEAK):
            findings.append(Finding(NAME, "mcp-error-leak", "low", "Malformed request leaks internals",
                                    target.url, category=CATEGORY, app=target.app,
                                    detail="The error response contains a stack trace or local path.",
                                    fix="Return a JSON-RPC error object; log details server-side only."))
    if not findings:
        findings.append(Finding(NAME, "mcp-posture-ok", "info", "MCP endpoint passed the posture checks",
                                target.url, category=CATEGORY, app=target.app))
    return findings
