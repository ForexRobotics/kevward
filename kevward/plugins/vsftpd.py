# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""vsftpd (#134): apt packages + anonymous login and TLS.

On top of the apt checks, ``/etc/vsftpd.conf`` is read as text (the server is
never contacted):

* MEDIUM: ``anonymous_enable=YES`` (anyone can log in).
* LOW: ``ssl_enable`` is not ``YES``, so passwords and files cross the
  network in clear text. Both default to NO.
"""

from __future__ import annotations

from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/vsftpd.conf")


def parse_conf(text: str) -> dict[str, str]:
    """``option=value`` lines of vsftpd.conf -> dict (upper-cased values,
    last one wins). Pure."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().lower()] = value.strip().upper()
    return out


def classify(conf: dict[str, str]) -> list[tuple[Severity, str, str]]:
    """``(severity, title, detail)`` for vsftpd.conf settings. Pure."""
    out: list[tuple[Severity, str, str]] = []
    if conf.get("anonymous_enable", "NO") == "YES":
        out.append((
            Severity.MEDIUM,
            "vsftpd allows anonymous login",
            "anonymous_enable=YES lets anyone log in. Set `anonymous_enable=NO` "
            "unless this is a deliberate public download server.",
        ))
    if conf.get("ssl_enable", "NO") != "YES":
        out.append((
            Severity.LOW,
            "vsftpd has no TLS",
            "Passwords and files cross the network in clear text. Set "
            "`ssl_enable=YES` with `rsa_cert_file`/`rsa_private_key_file`, or "
            "use SFTP instead.",
        ))
    return out


@register
class VsftpdPlugin(AptServicePlugin):
    name = "vsftpd"
    packages = ["vsftpd"]
    service_unit = "vsftpd.service"
    kev_terms = ["vsftpd"]

    def check(self) -> list[Finding]:
        findings = super().check()
        try:
            text = CONFIG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings
        findings.extend(
            Finding(service=self.name, kind=FindingKind.CONFIG, severity=sev,
                    title=title, detail=detail)
            for sev, title, detail in classify(parse_conf(text))
        )
        return findings
