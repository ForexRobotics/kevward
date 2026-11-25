# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Webmin (#137): apt packages + panel reachable from any address.

Webmin runs as root and has several CISA KEV entries (one a backdoored
release). It is installed from Webmin's own apt repository
(download.webmin.com), not Ubuntu's, so its pending updates are minor
upgrades unless that origin is listed in ``[apt] security_origins``; they are
never classified as Ubuntu security updates.

On top of the apt checks, ``/etc/webmin/miniserv.conf`` is read as text (the
panel is never contacted): LOW when it has no ``allow=`` restriction and does
not bind to loopback, i.e. the panel is reachable from any address.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/webmin/miniserv.conf")


def parse_miniserv(text: str) -> dict[str, str]:
    """``key=value`` lines of miniserv.conf -> dict (last one wins). Pure."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().lower()] = value.strip()
    return out


def is_loopback(host: str) -> bool:
    """localhost / 127.0.0.0/8 / ::1. Pure."""
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def classify(conf: dict[str, str]) -> list[tuple[Severity, str, str]]:
    """LOW when the panel accepts every address. Pure."""
    if conf.get("allow"):
        return []
    binds = conf.get("bind", "").split()
    if binds and all(is_loopback(b) for b in binds):
        return []
    port = conf.get("port", "10000")
    return [(
        Severity.LOW,
        f"Webmin panel (port {port}) reachable from any address",
        "/etc/webmin/miniserv.conf has no allow= restriction. Webmin runs as "
        "root; limit it to trusted addresses (Webmin > Webmin Configuration > "
        "IP Access Control, or allow=<addresses>) or bind=127.0.0.1 and use an "
        "SSH tunnel.",
    )]


@register
class WebminPlugin(AptServicePlugin):
    name = "webmin"
    packages = ["webmin"]
    service_unit = "webmin.service"
    kev_terms = ["webmin"]

    def check(self) -> list[Finding]:
        findings = super().check()
        try:
            text = CONFIG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings
        findings.extend(
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=sev,
                title=title,
                detail=detail,
            )
            for sev, title, detail in classify(parse_miniserv(text))
        )
        return findings
