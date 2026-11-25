# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""MongoDB (#127): apt packages + database open on every interface.

MongoDB is normally installed from MongoDB's own apt repository
(repo.mongodb.org), not Ubuntu's, so its pending updates are not classified
as Ubuntu security updates: they show up as minor upgrades unless that origin
is listed in ``[apt] security_origins``.

On top of the apt checks, ``/etc/mongod.conf`` is read as text (a small
YAML subset, no YAML dependency; the database is never contacted): MEDIUM
when ``net.bindIp`` includes ``0.0.0.0`` / ``::`` (or ``net.bindIpAll`` is
true) and access control is off (``security.authorization`` not
``enabled`` and no ``security.keyFile``, which also turns it on).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/mongod.conf")
WILDCARD = {"0.0.0.0", "::", "*"}


def _scalar(value: str) -> str:
    value = re.sub(r"\s+#.*$", "", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def parse_conf(text: str) -> dict[str, str]:
    """Block-style YAML of mongod.conf -> flat ``section.key`` dict. Pure.

    Only what mongod.conf uses: nested ``key: value`` mappings by
    indentation, comments and quoted scalars. Flow-style mappings
    (``net: {bindIp: ...}``) are not expanded.
    """
    out: dict[str, str] = {}
    stack: list[tuple[int, str]] = []
    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)([A-Za-z0-9_.]+)\s*:(.*)$", raw)
        if not m:
            continue
        indent, key, rest = len(m.group(1).expandtabs()), m.group(2), m.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = ".".join([k for _, k in stack] + [key])
        value = _scalar(rest)
        if value:
            out[path] = value
        else:
            stack.append((indent, key))
    return out


def exposed_without_auth(conf: dict[str, str]) -> str | None:
    """Where mongod listens when it is open on every interface without access
    control, else None. Pure."""
    auth = conf.get("security.authorization", "").lower() == "enabled"
    if auth or conf.get("security.keyFile"):
        return None
    if conf.get("net.bindIpAll", "").lower() == "true":
        return "all interfaces (bindIpAll)"
    binds = [b.strip() for b in conf.get("net.bindIp", "").split(",") if b.strip()]
    wild = [b for b in binds if b in WILDCARD]
    return ", ".join(wild) if wild else None


@register
class MongodbPlugin(AptServicePlugin):
    name = "mongodb"
    packages = ["mongodb-org-server", "mongodb-org-mongos", "mongodb-org"]
    service_unit = "mongod.service"
    kev_terms = ["mongodb"]

    def check(self) -> list[Finding]:
        findings = super().check()
        try:
            text = CONFIG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings
        where = exposed_without_auth(parse_conf(text))
        if where:
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title=f"MongoDB listens on {where} without access control",
                    detail="Anyone who can reach port 27017 can read and change every "
                    "database. Set `security: authorization: enabled` in "
                    "/etc/mongod.conf (after creating an admin user), or bind to "
                    "127.0.0.1.",
                )
            )
        return findings
