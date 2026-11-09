# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Is a newer kevward release available? (#70)

Read-only: compares the installed version with the latest release on PyPI and
returns an INFO finding with the upgrade command. Never upgrades anything.

- One HTTPS GET to pypi.org, cached for 24h; stdlib only.
- Fail-soft and silent: offline, timeouts, bad JSON -> no finding.
- Opt out with ``[update] check = false`` (air-gapped hosts).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

from .. import __version__
from ..model import Finding, FindingKind, Severity

PYPI_URL = "https://pypi.org/pypi/kevward/json"
CACHE_TTL = 24 * 3600
SYSTEM_CACHE = Path("/var/cache/kevward/pypi-latest.json")

_REL = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def parse_version(v: str) -> tuple[tuple[int, ...], bool] | None:
    """'0.12.5' -> ((0, 12, 5), False); '0.13.0rc1' -> ((0, 13, 0), True).
    None for anything that does not start with a numeric release."""
    m = _REL.match((v or "").strip().lstrip("vV"))
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    while len(nums) > 1 and nums[-1] == 0:  # 1.0 == 1.0.0
        nums = nums[:-1]
    return nums, bool(m.group(2).strip())


def is_newer(installed: str, latest: str) -> bool:
    """True if ``latest`` is a newer release than ``installed``. Pre-releases
    are ignored unless the installed version is itself a pre-release."""
    a, b = parse_version(installed), parse_version(latest)
    if a is None or b is None:
        return False
    (a_nums, a_pre), (b_nums, b_pre) = a, b
    if b_pre and not a_pre:
        return False
    if b_nums != a_nums:
        return b_nums > a_nums
    return a_pre and not b_pre  # 0.13.0rc1 -> 0.13.0


def _cache_file() -> Path:
    if os.access(SYSTEM_CACHE.parent, os.W_OK) or SYSTEM_CACHE.is_file():
        return SYSTEM_CACHE
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kevward" / "pypi-latest.json"


def latest_release(timeout: float = 5.0) -> str | None:
    """Latest kevward version on PyPI (cached 24h), or None if unknown."""
    cf = _cache_file()
    try:
        if cf.is_file() and time.time() - cf.stat().st_mtime < CACHE_TTL:
            return json.loads(cf.read_text()).get("version")
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(PYPI_URL, headers={"User-Agent": "kevward"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            ver = json.loads(resp.read().decode())["info"]["version"]
    except Exception:
        try:  # offline: a stale cached answer is still better than nothing
            return json.loads(cf.read_text()).get("version")
        except (OSError, ValueError):
            return None
    try:
        cf.parent.mkdir(parents=True, exist_ok=True)
        cf.write_text(json.dumps({"version": ver}))
    except OSError:
        pass
    return ver


def upgrade_command(prefix: str | None = None) -> str:
    """The pip command matching how this kevward is installed."""
    prefix = prefix or sys.prefix
    in_venv = prefix != getattr(sys, "base_prefix", prefix)
    pip = f"{prefix}/bin/pip" if in_venv else "pip"
    return f"sudo {pip} install -U kevward"


def update_findings(installed: str = __version__, latest: str | None = None,
                    prefix: str | None = None) -> list[Finding]:
    """One INFO finding when a newer release exists, else []."""
    if latest is None:
        latest = latest_release()
    if not latest or not is_newer(installed, latest):
        return []
    return [
        Finding(
            service="kevward",
            kind=FindingKind.CONFIG,
            severity=Severity.INFO,
            title=f"kevward {installed} installed, {latest} available",
            detail=f"Upgrade with `{upgrade_command(prefix)}` "
            "(see CHANGELOG.md for what changed).",
            current_version=installed,
            fixed_version=latest,
        )
    ]
