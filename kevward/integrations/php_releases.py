# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Is a pending PHP upgrade a PHP security release? (#169)

PHP from a third-party repository (the ondrej/php PPA, packages.sury.org)
comes from an apt origin such as ``LP-PPA-ondrej-php``, which never contains
"security". kevward used to classify every such update as a minor upgrade, so
the 2026-11-19 PHP releases fixing seven critical CVEs showed as ``low`` and
``kevward apply`` skipped them.

This module maps the upstream PHP version of an apt candidate
(``8.3.37`` from ``8.3.37-2+ubuntu22.04.1+deb.sury.org+1``) to php.net's
release data, where security releases carry the ``security`` tag.

- One HTTPS GET per PHP branch to www.php.net, cached for 12h; stdlib only.
- Fail-soft: offline, timeouts or unexpected JSON -> "unknown" (None), and
  the caller keeps the update as a minor upgrade but says the security status
  was not checked. A stale cache is used when the network is down.
- Opt out with ``[apt] php_release_check = false`` (air-gapped hosts).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

RELEASES_URL = "https://www.php.net/releases/index.php?json&version={branch}&max=100"
ANNOUNCE_URL = "https://www.php.net/releases/{under}.php"
CACHE_TTL = 12 * 3600
SYSTEM_CACHE_DIR = Path("/var/cache/kevward")

# php8.3, php8.3-fpm, libapache2-mod-php8.3, libphp8.3-embed (not php-common,
# php-pear, ...: those are version-less and not tied to one PHP release).
_PKG = re.compile(r"^(?:php|libapache2-mod-php|libphp)(\d+\.\d+)(?:-|$)")
_UPSTREAM = re.compile(r"^(?:\d+:)?(\d+\.\d+\.\d+)")
_BRANCH = re.compile(r"^\d+\.\d+$")


def php_branch(pkg: str) -> str | None:
    """'php8.3-fpm' -> '8.3'; None for packages not tied to a PHP branch. Pure."""
    m = _PKG.match(pkg or "")
    return m.group(1) if m else None


def upstream_version(debver: str) -> str | None:
    """'1:8.3.37-2+ubuntu22.04.1+deb.sury.org+1' -> '8.3.37'. Pure."""
    m = _UPSTREAM.match((debver or "").strip())
    return m.group(1) if m else None


def _key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def parse_releases(data: object, branch: str) -> dict[str, bool] | None:
    """php.net JSON -> {version: is_security_release} for one branch. Pure.

    The API returns an object keyed by version, e.g.
    ``{"8.3.37": {"tags": ["security"], "date": "19 Nov 2026", ...}}``.
    None when the shape is not recognised (so callers say "unchecked").
    """
    if not isinstance(data, dict):
        return None
    out: dict[str, bool] = {}
    tagged = False
    for ver, info in data.items():
        if not isinstance(ver, str) or not isinstance(info, dict):
            continue
        if not re.fullmatch(r"\d+\.\d+\.\d+", ver) or not ver.startswith(branch + "."):
            continue
        tags = info.get("tags")
        tagged = tagged or isinstance(tags, list)
        out[ver] = isinstance(tags, list) and "security" in tags
    # No entry carries a "tags" list at all: the format changed, and treating
    # every release as a bugfix one would silently hide security releases.
    return out if out and tagged else None


def security_releases_between(releases: dict[str, bool] | None, cur: str,
                              new: str) -> list[str] | None:
    """Security releases v with cur < v <= new, oldest first. Pure.

    None (= unknown) when the release data is missing or does not know the
    candidate version yet; [] when every release in between is a bugfix one.
    """
    if not releases or new not in releases:
        return None
    lo, hi = _key(cur), _key(new)
    return sorted((v for v, sec in releases.items() if sec and lo < _key(v) <= hi),
                  key=_key)


def announcement_url(version: str) -> str:
    return ANNOUNCE_URL.format(under=version.replace(".", "_"))


def _cache_file(branch: str) -> Path:
    name = f"php-releases-{branch}.json"
    sys_file = SYSTEM_CACHE_DIR / name
    if os.access(SYSTEM_CACHE_DIR, os.W_OK) or sys_file.is_file():
        return sys_file
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kevward" / name


@lru_cache(maxsize=16)
def fetch_releases(branch: str, timeout: float = 8.0) -> dict[str, bool] | None:
    """Release data for one PHP branch (cached 12h on disk, once per process)."""
    if not _BRANCH.match(branch or ""):
        return None
    cf = _cache_file(branch)
    try:
        if cf.is_file() and time.time() - cf.stat().st_mtime < CACHE_TTL:
            return parse_releases(json.loads(cf.read_text()), branch)
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(RELEASES_URL.format(branch=branch),
                                     headers={"User-Agent": "kevward"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = json.loads(resp.read().decode())
    except Exception:
        try:  # offline: a stale cached answer is still better than nothing
            return parse_releases(json.loads(cf.read_text()), branch)
        except (OSError, ValueError):
            return None
    parsed = parse_releases(raw, branch)
    if parsed is not None:
        try:
            cf.parent.mkdir(parents=True, exist_ok=True)
            cf.write_text(json.dumps(raw))
        except OSError:
            pass
    return parsed


def classify(changes: list[dict], fetch=fetch_releases) -> None:
    """Mark pending PHP upgrades that contain a PHP security release.

    For each non-security change of a branch-specific PHP package whose
    upstream version moves (8.3.36 -> 8.3.37): set ``security`` and a
    ``security_why`` / ``url`` when php.net tags a release in between as
    security; set ``security_unchecked`` when that could not be determined.
    Changes from an origin already marked security, and Debian-revision-only
    updates (Ubuntu archive backports), are left alone. Mutates ``changes``.
    """
    for c in changes:
        if c.get("security"):
            continue
        branch = php_branch(c.get("pkg", ""))
        cur, new = upstream_version(c.get("cur", "")), upstream_version(c.get("new", ""))
        if not branch or not cur or not new or _key(new) <= _key(cur):
            continue
        sec = security_releases_between(fetch(branch), cur, new)
        if sec is None:
            c["security_unchecked"] = (
                f"security status unchecked: php.net release data for PHP {branch} "
                f"was not available or does not list {new} yet")
        elif sec:
            c["security"] = True
            verb = "is a security release" if len(sec) == 1 else "are security releases"
            c["security_why"] = (
                f"PHP {', '.join(sec)} {verb} (php.net), although the apt origin "
                "is not a security pocket")
            c["url"] = announcement_url(sec[-1])
