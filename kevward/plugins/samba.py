# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Samba (#133): apt packages + SMB1 and interface restriction.

Samba appears repeatedly in CISA KEV and should never face the internet. On
top of the apt checks, the effective ``[global]`` settings from ``testparm -s``
(read-only: it only parses smb.conf) are checked:

* LOW: ``server min protocol`` allows SMB1 (``NT1`` or lower). The default
  has been SMB2 since Samba 4.11, so only an explicit setting counts.
* LOW: no ``interfaces`` + ``bind interfaces only = yes`` restriction, i.e.
  smbd listens on every interface.
"""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin

# SMB dialects up to and including SMB1 (NT1), oldest first.
SMB1_OR_LOWER = {"core", "coreplus", "lanman1", "lanman2", "nt1"}


def parse_global(text: str) -> dict[str, str]:
    """``testparm -s`` output -> the ``[global]`` parameters (lower-cased
    keys, single spaces). Pure."""
    out: dict[str, str] = {}
    section = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section == "global" and "=" in line:
            key, _, value = line.partition("=")
            out[" ".join(key.lower().split())] = value.strip()
    return out


def _yes(value: str) -> bool:
    return value.strip().lower() in {"yes", "true", "1", "on"}


def classify(glob: dict[str, str]) -> list[tuple[Severity, str, str]]:
    """``(severity, title, detail)`` for the ``[global]`` settings. Pure."""
    out: list[tuple[Severity, str, str]] = []
    minproto = glob.get("server min protocol", glob.get("min protocol", "")).lower()
    if minproto in SMB1_OR_LOWER:
        out.append((
            Severity.LOW,
            f"Samba allows SMB1 (server min protocol = {minproto.upper()})",
            "SMB1 is deprecated and was the vector for EternalBlue-style attacks. "
            "Remove the setting or set `server min protocol = SMB2_02`.",
        ))
    if not (glob.get("interfaces") and _yes(glob.get("bind interfaces only", ""))):
        out.append((
            Severity.LOW,
            "Samba listens on every interface",
            "No `interfaces` + `bind interfaces only = yes` restriction in "
            "smb.conf. Limit smbd to the LAN interfaces and never expose SMB "
            "to the internet.",
        ))
    return out


@register
class SambaPlugin(AptServicePlugin):
    name = "samba"
    packages = ["samba", "samba-common-bin"]
    service_unit = "smbd.service"
    kev_terms = ["samba"]

    def check(self) -> list[Finding]:
        findings = super().check()
        res = run(["testparm", "-s"], timeout=30)
        if not res.ok:
            return findings
        findings.extend(
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=sev,
                title=title,
                detail=detail,
            )
            for sev, title, detail in classify(parse_global(res.out))
        )
        return findings
