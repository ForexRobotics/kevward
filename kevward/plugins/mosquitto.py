# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Eclipse Mosquitto (MQTT broker, #128): apt packages + listener exposure.

On top of the apt checks, the config (``/etc/mosquitto/mosquitto.conf`` and
its ``include_dir``) is read as text, never by connecting to the broker:

* MEDIUM: a listener on a non-loopback address accepts anonymous clients
  (anyone on the network can read and publish every topic).
* LOW: a non-loopback listener has no TLS (``certfile``/``keyfile`` or PSK).

Mosquitto 2.x defaults are respected: ``allow_anonymous false``, and with no
listener configured it only listens on loopback. 1.x defaulted to anonymous
access on all interfaces. ``per_listener_settings`` decides whether
``allow_anonymous`` is global or per listener.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ._apt import AptServicePlugin

CONFIG = Path("/etc/mosquitto/mosquitto.conf")


@dataclass
class Listener:
    port: str
    address: str = ""          # "" = every interface
    interface: str = ""        # bind_interface
    anonymous: bool | None = None
    tls: bool = False

    @property
    def local(self) -> bool:
        if self.port == "0" or self.address.startswith("/"):
            return True        # a unix socket
        if self.interface:
            return self.interface == "lo"
        return bool(self.address) and is_loopback(self.address)

    @property
    def where(self) -> str:
        if self.interface:
            return f"port {self.port} on interface {self.interface}"
        return f"{self.address or 'all interfaces'}:{self.port}"


def is_loopback(host: str) -> bool:
    """localhost / 127.0.0.0/8 / ::1. Pure."""
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _bool(value: str) -> bool:
    return value.strip().lower() == "true"


def parse_listeners(text: str, major: int = 2) -> list[Listener]:
    """The listeners a mosquitto config sets up, with the effective
    ``allow_anonymous`` and TLS of each. Pure.

    ``text`` is the main file with its ``include_dir`` files appended in the
    order mosquitto reads them. ``major`` is the mosquitto major version (it
    decides the ``allow_anonymous`` default). With no ``listener`` and no
    ``port``/``bind_address``, 2.x listens on loopback only: no listeners are
    returned for it, as nothing is reachable from the network. 1.x always
    opens the default listener on every interface.
    """
    per_listener = False
    default = Listener(port="1883")
    default_used = False
    default_anon: bool | None = None
    global_anon: bool | None = None
    listeners: list[Listener] = []
    current: Listener | None = None

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        key, value = key.lower(), value.strip()
        target = current or default
        if key == "per_listener_settings":
            per_listener = _bool(value)
        elif key == "listener":
            parts = value.split()
            current = Listener(port=parts[0] if parts else "1883",
                               address=parts[1] if len(parts) > 1 else "")
            listeners.append(current)
        elif key == "port" and value:
            default.port, default_used = value, True
        elif key == "bind_address" and value:
            default.address, default_used = value, True
        elif key == "bind_interface" and value:
            target.interface = value
        elif key == "allow_anonymous":
            global_anon = _bool(value)
            if current is None:
                default_anon = global_anon
            else:
                current.anonymous = global_anon
        elif key in {"certfile", "psk_hint"} and value:
            target.tls = True

    if default_used or major < 2:
        default.anonymous = default_anon
        listeners.insert(0, default)

    fallback = major < 2
    for ln in listeners:
        if per_listener:
            ln.anonymous = fallback if ln.anonymous is None else ln.anonymous
        else:
            ln.anonymous = fallback if global_anon is None else global_anon
    return listeners


def classify_listeners(listeners: list[Listener]) -> list[tuple[Severity, str, str]]:
    """``(severity, title, detail)`` for exposed listeners. Pure."""
    out: list[tuple[Severity, str, str]] = []
    for ln in listeners:
        if ln.local:
            continue
        if ln.anonymous:
            out.append((
                Severity.MEDIUM,
                f"Mosquitto listener {ln.where} allows anonymous clients",
                "Anyone who can reach it can read and publish every topic. Set "
                "`allow_anonymous false` with a `password_file`, or bind it to "
                "127.0.0.1.",
            ))
        if not ln.tls:
            out.append((
                Severity.LOW,
                f"Mosquitto listener {ln.where} has no TLS",
                "Credentials and messages cross the network in clear text. Add "
                "`certfile`/`keyfile` to the listener (usually on port 8883).",
            ))
    return out


def read_config(path: Path = CONFIG) -> str:
    """The main config plus its ``include_dir`` *.conf files (sorted, as
    mosquitto does), as one text. Missing or unreadable files are skipped."""
    try:
        main = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    parts = [main]
    for m in re.finditer(r"^\s*include_dir\s+(\S.*?)\s*$", main, re.MULTILINE):
        d = Path(m.group(1))
        try:
            files = sorted(p for p in d.iterdir() if p.suffix == ".conf" and p.is_file())
        except OSError:
            continue
        for f in files:
            try:
                parts.append(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(parts)


def major_version(version: str | None) -> int:
    """'mosquitto 2.0.18-1ubuntu1' -> 2; 2 when unknown. Pure."""
    m = re.search(r"(?:^|\s|:)(\d+)\.\d+", version or "")
    return int(m.group(1)) if m else 2


@register
class MosquittoPlugin(AptServicePlugin):
    name = "mosquitto"
    packages = ["mosquitto"]
    service_unit = "mosquitto.service"
    kev_terms = ["mosquitto"]

    def check(self) -> list[Finding]:
        findings = super().check()
        listeners = parse_listeners(read_config(), major_version(self.version()))
        findings.extend(
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=sev,
                title=title,
                detail=detail,
            )
            for sev, title, detail in classify_listeners(listeners)
        )
        return findings
