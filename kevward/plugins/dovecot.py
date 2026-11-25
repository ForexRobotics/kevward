# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Dovecot (#130): apt packages + clear-text passwords.

On top of the apt checks, ``doveconf -n`` (read-only: it prints the settings
that differ from the defaults) is checked: MEDIUM when plain-text
authentication is allowed without TLS (``disable_plaintext_auth = no``, or
``auth_allow_cleartext = yes`` in Dovecot 2.4, together with ``ssl = no``),
so mailbox passwords can cross the network in clear text. Only top-level
settings count; ``protocol``/``service`` blocks are not followed.
"""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin


def parse_doveconf(text: str) -> dict[str, str]:
    """Top-level ``key = value`` settings from ``doveconf -n``. Pure."""
    out: dict[str, str] = {}
    depth = 0
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("{"):
            depth += 1
            continue
        if line == "}":
            depth = max(0, depth - 1)
            continue
        if depth == 0 and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().lower()
    return out


def cleartext_passwords(conf: dict[str, str]) -> bool:
    """Plain-text auth allowed and TLS off. Pure."""
    plaintext = (conf.get("disable_plaintext_auth") == "no"
                 or conf.get("auth_allow_cleartext") == "yes")
    return plaintext and conf.get("ssl") == "no"


@register
class DovecotPlugin(AptServicePlugin):
    name = "dovecot"
    packages = ["dovecot-core", "dovecot-imapd", "dovecot-pop3d"]
    service_unit = "dovecot.service"
    kev_terms = ["dovecot"]

    def check(self) -> list[Finding]:
        findings = super().check()
        res = run(["doveconf", "-n"], timeout=30)
        if res.ok and cleartext_passwords(parse_doveconf(res.out)):
            findings.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title="Dovecot accepts passwords in clear text",
                    detail="Plain-text authentication is allowed and ssl = no, so "
                    "mailbox passwords cross the network unencrypted. Enable "
                    "`ssl = required` with a certificate, and keep "
                    "`disable_plaintext_auth = yes`.",
                )
            )
        return findings
