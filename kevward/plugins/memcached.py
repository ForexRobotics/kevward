# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Memcached (#136): apt packages + listener exposure.

Memcached has no authentication by default, so on top of the apt checks
``/etc/memcached.conf`` (the Debian/Ubuntu option file) is read as text,
never by connecting to the service:

* MEDIUM: ``-l`` is missing (every interface) or binds a non-loopback address.
* LOW: UDP is on while the service is reachable from the network (it has been
  abused for very large DDoS amplification). UDP is off by default since
  memcached 1.5.6, so it counts as on only with ``-U <port>`` other than 0,
  or on older versions without ``-U 0``.

A unix socket (``-s``) turns the network listeners off: no findings then.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/memcached.conf")
UDP_OFF_SINCE = (1, 5, 6)


@dataclass
class MemcachedConf:
    listen: list[str] = field(default_factory=list)
    udp_port: str | None = None
    socket: str | None = None


def parse_conf(text: str) -> MemcachedConf:
    """``/etc/memcached.conf`` (one option per line, ``#`` comments) -> the
    listen addresses, UDP port and unix socket. Pure."""
    conf = MemcachedConf()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"(-[lUs]|--listen|--udp-port|--unix-socket)(?:[=\s]+(\S+))?$", line)
        if not m or not m.group(2):
            continue
        opt, value = m.groups()
        if opt in {"-l", "--listen"}:
            conf.listen.extend(a for a in value.split(",") if a)
        elif opt in {"-U", "--udp-port"}:
            conf.udp_port = value
        else:
            conf.socket = value
    return conf


def _host(addr: str) -> str:
    """'127.0.0.1:11211' -> '127.0.0.1', '[::1]:11211' -> '::1', '::1' -> '::1'."""
    if addr.startswith("["):
        return addr[1:].split("]", 1)[0]
    if addr.count(":") == 1:
        return addr.split(":", 1)[0]
    return addr


def is_loopback(host: str) -> bool:
    """localhost / 127.0.0.0/8 / ::1. Pure."""
    h = host.strip().lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def parse_version(version: str | None) -> tuple[int, ...] | None:
    """'memcached 1.6.14-1ubuntu0.1' -> (1, 6, 14); None when unknown. Pure."""
    m = re.search(r"(?:^|\s|:)(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(x) for x in m.groups()) if m else None


def classify(conf: MemcachedConf,
             version: tuple[int, ...] | None = None) -> list[tuple[Severity, str, str]]:
    """``(severity, title, detail)`` for an exposed memcached. Pure."""
    if conf.socket:
        return []
    exposed = [a for a in conf.listen if not is_loopback(_host(a))]
    if conf.listen and not exposed:
        return []
    where = ", ".join(exposed) if exposed else "all interfaces (no -l)"
    out = [(
        Severity.MEDIUM,
        f"Memcached listens on {where}",
        "Memcached has no authentication: anyone who can reach it can read and "
        "change the cache. Set `-l 127.0.0.1` in /etc/memcached.conf, or "
        "firewall the port.",
    )]
    if conf.udp_port is not None:
        udp_on = conf.udp_port != "0"
    else:
        udp_on = version is not None and version < UDP_OFF_SINCE
    if udp_on:
        out.append((
            Severity.LOW,
            "Memcached UDP is enabled",
            "UDP memcached has been abused for very large DDoS amplification. "
            "Add `-U 0` to /etc/memcached.conf.",
        ))
    return out


@register
class MemcachedPlugin(AptServicePlugin):
    name = "memcached"
    packages = ["memcached"]
    service_unit = "memcached.service"
    kev_terms = ["memcached"]

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
            for sev, title, detail in classify(parse_conf(text),
                                               parse_version(self.version()))
        )
        return findings
