# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Node-RED (#140): version and an editor reachable without ``adminAuth``.

Node-RED is installed with npm (globally or per user), not apt, and runs as
``nodered.service`` or a custom unit. Its flow editor can run arbitrary code,
so an editor listening on a non-loopback address without ``adminAuth`` is in
effect a remote shell: that is a MEDIUM finding.

``settings.js`` is JavaScript, but kevward only reads it as text: comments are
stripped and the ``adminAuth`` / ``uiHost`` / ``disableEditor`` keys looked up.
It is never executed. Report-only.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import ServicePlugin, register

GLOBAL_PACKAGES = [
    Path("/usr/lib/node_modules/node-red/package.json"),
    Path("/usr/local/lib/node_modules/node-red/package.json"),
]
SERVICE_UNITS = [
    Path("/etc/systemd/system/nodered.service"),
    Path("/lib/systemd/system/nodered.service"),
    Path("/usr/lib/systemd/system/nodered.service"),
]
HOMES = [Path("/root"), Path("/home")]

_UNKNOWN = object()


def strip_js_comments(text: str) -> str:
    """``text`` without ``//`` and ``/* */`` comments. Pure.

    Quoted strings are kept as they are, so ``"http://host"`` survives.
    A newline ends a line comment and is kept (line numbers stay the same).
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote = ""
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
        elif c in "\"'`":
            quote = c
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_version(package_json: str) -> str | None:
    """The ``version`` of a ``package.json``, or None. Pure."""
    try:
        data = json.loads(package_json)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    v = data.get("version") if isinstance(data, dict) else None
    return v if isinstance(v, str) and v else None


def has_admin_auth(settings: str) -> bool:
    """Is ``adminAuth`` set (not commented out, not null/false) in settings.js? Pure."""
    code = strip_js_comments(settings)
    for m in re.finditer(r"""(?<![\w$.])["']?adminAuth["']?\s*:\s*([^\s,}]*)""", code):
        if m.group(1) not in {"null", "undefined", "false"}:
            return True
    return False


def editor_disabled(settings: str) -> bool:
    """``disableEditor: true`` in settings.js. Pure."""
    code = strip_js_comments(settings)
    return re.search(r"""(?<![\w$.])["']?disableEditor["']?\s*:\s*true\b""", code) is not None


def ui_host(settings: str):
    """The literal ``uiHost`` in settings.js, None when it is not set (Node-RED
    then listens on every interface), or ``_UNKNOWN`` when it is not a string
    literal (e.g. read from an environment variable). Pure."""
    code = strip_js_comments(settings)
    m = re.search(r"""(?<![\w$.])["']?uiHost["']?\s*:\s*(["'`])?([^,}\n]*)""", code)
    if not m:
        return None
    if not m.group(1):
        return _UNKNOWN
    value = m.group(2).split(m.group(1), 1)[0].strip()
    return value if "${" not in value else _UNKNOWN


def is_loopback(host: str) -> bool:
    """localhost / 127.0.0.0/8 / ::1. Pure."""
    h = host.strip().strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def editor_exposed(settings: str) -> str | None:
    """Where the editor listens when it is open without ``adminAuth`` on a
    non-loopback address, else None (protected, local only or unknown). Pure."""
    if has_admin_auth(settings) or editor_disabled(settings):
        return None
    host = ui_host(settings)
    if host is _UNKNOWN:
        return None
    if host is None:
        return "all interfaces (no uiHost)"
    if is_loopback(host):
        return None
    return host or "all interfaces"


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def user_dirs(homes: list[Path] | None = None) -> list[Path]:
    """Every ``~/.node-red`` under /root and /home/* (that we can see)."""
    homes = HOMES if homes is None else homes
    found: list[Path] = []
    candidates = [Path.home() / ".node-red"]
    for base in homes:
        candidates.append(base / ".node-red")
        try:
            candidates.extend(p / ".node-red" for p in sorted(base.iterdir()) if p.is_dir())
        except OSError:
            continue
    for c in candidates:
        try:
            if c.is_dir() and c not in found:
                found.append(c)
        except OSError:
            continue
    return found


@register
class NodeRedPlugin(ServicePlugin):
    name = "nodered"
    supports_apply = False
    kev_terms = ["node-red"]

    def _packages(self) -> list[Path]:
        paths = list(GLOBAL_PACKAGES)
        paths += [d / "node_modules" / "node-red" / "package.json" for d in user_dirs()]
        return [p for p in paths if p.is_file()]

    def detect(self) -> bool:
        return bool(
            self._packages()
            or any(u.is_file() for u in SERVICE_UNITS)
            or user_dirs()
        )

    def version(self) -> str | None:
        for p in self._packages():
            v = parse_version(_read(p) or "")
            if v:
                return v
        return None

    def check(self) -> list[Finding]:
        v = self.version()
        findings = [
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=Severity.INFO,
                title=f"Node-RED {v}" if v else "Node-RED (version unknown)",
                detail="Installed with npm, so apt does not update it: "
                "`npm install -g --unsafe-perm node-red` (or the Node-RED update script).",
                current_version=v,
            )
        ]
        for d in user_dirs():
            text = _read(d / "settings.js")
            where = editor_exposed(text) if text is not None else None
            if where:
                findings.append(
                    Finding(
                        service=self.name,
                        kind=FindingKind.CONFIG,
                        severity=Severity.MEDIUM,
                        title="Node-RED editor reachable without adminAuth",
                        detail=f"{d / 'settings.js'}: no active adminAuth and the editor "
                        f"listens on {where}. The editor can run any code; set adminAuth, "
                        "or uiHost: \"127.0.0.1\", or disableEditor: true.",
                        current_version=v,
                    )
                )
        return findings
