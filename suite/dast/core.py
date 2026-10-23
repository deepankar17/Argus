"""Shared pieces for the dynamic scanners: the Target model and the authorization gate.

The gate is the safety boundary. A dynamic scanner must call `authorize(target, intrusive=...)`
before it touches a service, and honor the result:
  - a target must exist in config/dast.json with `authorized: true`;
  - `intrusive=True` (active scans: fuzzing, injection, auth abuse, rate-limit probing) is allowed
    only when the target's env is "local" or "staging", OR the run was explicitly started with
    allow_prod_active AND the target opts in with `allow_active: true`.
This keeps a careless run from launching an attack against production.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit


class NotAuthorized(Exception):
    """A dynamic scan was refused by the gate. Carries a human-readable reason."""


@dataclass
class Target:
    name: str
    kind: str                      # web | tls | http-api | mcp | firebase-emulator
    url: str = ""
    env: str = "prod"             # local | staging | prod
    authorized: bool = False       # the owner marked this target OK to test
    allow_active: bool = False     # the owner OK'd intrusive testing of THIS target
    app: str = ""
    token: str = ""               # for an authenticated endpoint (read from env refs, not committed)
    headers: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    @property
    def host(self):
        return urlsplit(self.url).netloc or self.url


def authorize(target: Target, intrusive: bool, allow_prod_active: bool = False):
    """Raise NotAuthorized unless this exact action is permitted. Called by every scanner."""
    if not target.authorized:
        raise NotAuthorized("target %r is not marked authorized in config/dast.json" % target.name)
    if intrusive:
        if target.env == "prod" and not (allow_prod_active and target.allow_active):
            raise NotAuthorized(
                "active/intrusive testing of %r is refused: it is a prod target. Point it at staging, "
                "or set allow_active on the target and start the run with --allow-prod-active." % target.name)
        if target.env not in ("local", "staging", "prod"):
            raise NotAuthorized("unknown env %r for target %r" % (target.env, target.name))
    return True
