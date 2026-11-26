# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""ProFTPD (#134): apt packages + anonymous login and TLS.

The package is ``proftpd-basic`` on Ubuntu 22.04 and ``proftpd-core`` on
24.04, so both are listed. On top of the apt checks,
``/etc/proftpd/proftpd.conf`` and the files it ``Include``s are read as text
(the server is never contacted):

* MEDIUM: an ``<Anonymous>`` block (anonymous login).
* LOW: no ``TLSEngine on`` (mod_tls off), so passwords and files cross the
  network in clear text. Ubuntu ships ``tls.conf`` with the Include
  commented out.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/proftpd/proftpd.conf")


def _code(text: str) -> list[str]:
    return [ln.split("#", 1)[0].strip() for ln in (text or "").splitlines()
            if ln.split("#", 1)[0].strip()]


def classify(text: str) -> list[tuple[Severity, str, str]]:
    """``(severity, title, detail)`` for the full config text. Pure."""
    lines = _code(text)
    out: list[tuple[Severity, str, str]] = []
    if any(re.match(r"<Anonymous\b", ln, re.I) for ln in lines):
        out.append((
            Severity.MEDIUM,
            "ProFTPD allows anonymous login",
            "The config has an <Anonymous> block, so anyone can log in. Remove it "
            "unless this is a deliberate public download server.",
        ))
    if not any(re.fullmatch(r"TLSEngine\s+on", ln, re.I) for ln in lines):
        out.append((
            Severity.LOW,
            "ProFTPD has no TLS",
            "Passwords and files cross the network in clear text. Enable mod_tls "
            "(`Include /etc/proftpd/tls.conf` with `TLSEngine on`), or use SFTP.",
        ))
    return out


def _included(spec: str, base: Path) -> list[Path]:
    p = Path(spec.strip().strip("\"'"))
    if not p.is_absolute():
        p = base / p
    try:
        if p.is_dir():
            return sorted(f for f in p.iterdir() if f.is_file())
        if any(c in p.name for c in "*?["):
            return sorted(f for f in p.parent.glob(p.name) if f.is_file())
        return [p] if p.is_file() else []
    except OSError:
        return []


def read_config(path: Path = CONFIG, _depth: int = 0) -> str:
    """The config with every (uncommented) ``Include`` inlined. Missing or
    unreadable files are skipped; includes are followed 5 levels deep."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    parts = [text]
    if _depth < 5:
        for ln in _code(text):
            m = re.match(r"Include\s+(.+)$", ln, re.I)
            if m:
                parts.extend(read_config(f, _depth + 1)
                             for f in _included(m.group(1), path.parent))
    return "\n".join(parts)


@register
class ProftpdPlugin(AptServicePlugin):
    name = "proftpd"
    packages = ["proftpd-basic", "proftpd-core"]
    service_unit = "proftpd.service"
    kev_terms = ["proftpd"]

    def check(self) -> list[Finding]:
        findings = super().check()
        text = read_config()
        if not text:
            return findings
        findings.extend(
            Finding(service=self.name, kind=FindingKind.CONFIG, severity=sev,
                    title=title, detail=detail)
            for sev, title, detail in classify(text)
        )
        return findings
