# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Version-level KEV applicability (issue #3).

``trends.py`` matches CISA KEV entries to this host by vendor/product *name*,
which can only say a CVE is *possibly* relevant. This module adds an optional
layer that answers the sharper question — "is that CVE actually unpatched on
*this* host's installed versions?" — by cross-referencing Ubuntu's per-CVE
security data against the installed source-package versions.

Design (per issue #3):
- **Per-CVE, targeted.** Only the CVEs that already name-matched are looked up,
  via ``https://ubuntu.com/security/cves/<CVE>.json`` (no API key).
- **Offline-tolerant.** Each CVE's JSON is cached under ``/var/cache/kevward``;
  any network error falls back to cache, then fails soft (the caller keeps the
  name-level "possible" label — no regression).
- **Bounded.** A per-run count cap and a wall-clock budget keep the extra
  requests light and a report from hanging on a flaky network.
- **stdlib-only**, read-only: this only reads a public catalog and the local
  dpkg database. No credentials, no outbound host data.

The version comparison implements Debian's version-ordering algorithm in pure
Python (so it is unit-testable offline); at runtime ``dpkg --compare-versions``
is preferred when available.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..util import have, run

CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
CACHE_DIR = Path("/var/cache/kevward/usn")
# Fix-version status changes slowly. Kept above 24h on purpose: reports run
# once a day at the same time, so a 24h TTL made yesterday's cache "stale" on
# every run and each report re-fetched everything, hitting the time budget
# (CVEs left 'unchecked'). 36h lets a daily run reuse the previous day's data.
CACHE_TTL = 36 * 3600  # seconds

# Release statuses that mean "affected and not yet fixed on this release".
_VULN_STATUSES = {"needed", "pending", "deferred"}


# --------------------------------------------------------------------------- #
# Debian version comparison (pure Python; see deb-version(7) / dpkg verrevcmp)
# --------------------------------------------------------------------------- #
def _order(c: str) -> int:
    """Ordering weight of a single non-digit character: ``~`` sorts before
    everything (even end-of-string), letters before all other punctuation."""
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a: str, b: str) -> int:
    """Compare two upstream/revision fragments per Debian's algorithm."""
    ia, ib, la, lb = 0, 0, len(a), len(b)
    while ia < la or ib < lb:
        # Lexical (non-digit) run.
        while (ia < la and not a[ia].isdigit()) or (ib < lb and not b[ib].isdigit()):
            ca = a[ia] if ia < la else ""
            cb = b[ib] if ib < lb else ""
            oa = _order("" if ca.isdigit() else ca)
            ob = _order("" if cb.isdigit() else cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if not ca.isdigit():
                ia += 1
            if not cb.isdigit():
                ib += 1
        # Numeric run: strip leading zeros, then compare by length, then value.
        while ia < la and a[ia] == "0":
            ia += 1
        while ib < lb and b[ib] == "0":
            ib += 1
        da, db = "", ""
        while ia < la and a[ia].isdigit():
            da += a[ia]
            ia += 1
        while ib < lb and b[ib].isdigit():
            db += b[ib]
            ib += 1
        if len(da) != len(db):
            return -1 if len(da) < len(db) else 1
        if da != db:
            return -1 if da < db else 1
    return 0


def _split_epoch(v: str) -> tuple[int, str]:
    if ":" in v:
        head, _, rest = v.partition(":")
        try:
            return int(head), rest
        except ValueError:
            return 0, v
    return 0, v


def _split_upstream_rev(v: str) -> tuple[str, str]:
    if "-" in v:
        up, _, rev = v.rpartition("-")
        return up, rev
    return v, ""


def deb_compare(a: str, b: str) -> int:
    """Return -1/0/1 for Debian version strings ``a`` vs ``b``."""
    ea, ra = _split_epoch(a.strip())
    eb, rb = _split_epoch(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    ua, va = _split_upstream_rev(ra)
    ub, vb = _split_upstream_rev(rb)
    c = _cmp_fragment(ua, ub)
    if c:
        return c
    return _cmp_fragment(va, vb)


def version_lt(installed: str, fixed: str) -> bool:
    """True if ``installed`` is older than ``fixed``. Prefers dpkg at runtime,
    falls back to the pure-Python comparison (used by tests / dpkg-less hosts)."""
    if have("dpkg"):
        r = run(["dpkg", "--compare-versions", installed, "lt", fixed])
        if r.rc in (0, 1):
            return r.rc == 0
    return deb_compare(installed, fixed) < 0


# --------------------------------------------------------------------------- #
# Host facts
# --------------------------------------------------------------------------- #
def host_codename() -> str:
    """Ubuntu/Debian release codename (e.g. ``jammy``), or '' if undetermined."""
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("VERSION_CODENAME="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass
    return ""


def installed_source_versions() -> dict[str, str]:
    """Map every installed source package -> its (highest) installed version.

    Ubuntu's CVE data is keyed by *source* package and fixes are *source*
    versions, so we compare against source versions. ``${source:Version}`` /
    ``${source:Package}`` are empty when they equal the binary's, so we fall
    back to the binary fields."""
    if not have("dpkg-query"):
        return {}
    fmt = "${source:Package}\\t${source:Version}\\t${Package}\\t${Version}\\n"
    r = run(["dpkg-query", "-W", "-f=" + fmt])
    if not r.ok:
        return {}
    out: dict[str, str] = {}
    for line in r.out.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        src, srcver, pkg, ver = (p.strip() for p in parts)
        name = src or pkg
        version = srcver or ver
        if not name or not version:
            continue
        if name not in out or deb_compare(version, out[name]) > 0:
            out[name] = version
    return out


# --------------------------------------------------------------------------- #
# Per-CVE Ubuntu security data (cached, fail-soft)
# --------------------------------------------------------------------------- #
def _user_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kevward" / "usn"


def _writable(d: Path) -> bool:
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(d, os.W_OK | os.X_OK)


def cache_status() -> dict:
    """Where this run writes Ubuntu CVE data, and whether it can (#65).

    The system dir (``CACHE_DIR``) is root-only. A non-root run used to fail
    every write silently, so each run started cold and the same CVEs stayed
    'unchecked'. Now it falls back to a per-user cache; only when neither is
    writable is ``writable`` False, which callers surface to the user."""
    if _writable(CACHE_DIR):
        return {"dir": str(CACHE_DIR), "writable": True, "fallback": False}
    user = _user_cache_dir()
    if _writable(user):
        return {"dir": str(user), "writable": True, "fallback": True}
    return {"dir": str(CACHE_DIR), "writable": False, "fallback": False}


def _write_dir() -> Path | None:
    st = cache_status()
    return Path(st["dir"]) if st["writable"] else None


def _cache_path(cve: str) -> Path:
    """Newest existing cache file for ``cve`` across the write dir and the
    system dir (a non-root run can still read what a root run cached), else
    the path a write would use."""
    name = f"{cve.upper()}.json"
    wd = _write_dir()
    dirs = [d for d in (wd, CACHE_DIR) if d is not None]
    found = []
    for d in dict.fromkeys(dirs):
        f = d / name
        try:
            if f.is_file():
                found.append((f.stat().st_mtime, f))
        except OSError:
            pass
    if found:
        return max(found)[1]
    return (wd or CACHE_DIR) / name


def cache_state(cve: str) -> str:
    """'fresh', 'stale' or 'none' for ``cve``'s cached JSON (no network)."""
    cp = _cache_path(cve.strip().upper())
    try:
        if not cp.is_file():
            return "none"
        return "fresh" if (time.time() - cp.stat().st_mtime) < CACHE_TTL else "stale"
    except OSError:
        return "none"


def cached_cve(cve: str) -> dict | None:
    """``cve``'s cached JSON regardless of age, without touching the network.

    Used when the time budget is spent: fix-version data changes slowly, so a
    day-old answer beats reporting the CVE as unchecked."""
    cp = _cache_path(cve.strip().upper())
    try:
        if cp.is_file():
            return json.loads(cp.read_text())
    except (OSError, ValueError):
        pass
    return None


# Cached in place of a CVE JSON when ubuntu.com answers 404.
NOT_TRACKED = {"not_tracked_by_ubuntu": True, "packages": []}


def _write_cache(cp: Path, data: dict) -> None:
    wd = _write_dir()
    if wd is None:
        return  # reported once per run via cache_status(), not per CVE
    try:
        (wd / cp.name).write_text(json.dumps(data))
    except OSError:
        pass


def fetch_cve(cve: str, timeout: float = 8) -> dict | None:
    """Return Ubuntu's security JSON for ``cve``, or None. Uses a fresh cache
    entry when present; on a network error falls back to a stale one."""
    cve = cve.strip().upper()
    if not cve.startswith("CVE-"):
        return None
    cp = _cache_path(cve)
    try:
        if cp.is_file() and (time.time() - cp.stat().st_mtime) < CACHE_TTL:
            return json.loads(cp.read_text())
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(
            CVE_URL.format(cve=cve), headers={"User-Agent": "kevward"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
        _write_cache(cp, data)
        return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Ubuntu does not track this CVE (e.g. Composer/npm-only products,
            # or upstream versions Ubuntu never shipped). That is a definitive
            # answer, not a failed lookup: cache it so it is not re-fetched
            # every run, and let classify_cve label it 'possible'.
            data = dict(NOT_TRACKED)
            _write_cache(cp, data)
            return data
        try:
            if cp.is_file():
                return json.loads(cp.read_text())
        except (OSError, ValueError):
            pass
        return None
    except Exception:
        try:
            if cp.is_file():
                return json.loads(cp.read_text())
        except (OSError, ValueError):
            pass
        return None


def _status_for(pkg: dict, codename: str) -> dict | None:
    """The status entry for ``codename`` within a CVE-JSON package, or None."""
    for st in pkg.get("statuses") or []:
        rel = (st.get("release_codename") or st.get("release") or "").lower()
        if rel == codename:
            return st
    return None


def classify_cve(data: dict | None, codename: str, installed: dict[str, str]) -> str:
    """Decide a name-matched CVE's applicability for this host.

    Returns ``"applicable"`` (an installed source package is affected and not
    fixed), ``"fixed"`` (every installed affected package is at/after its fix),
    or ``"possible"`` (no installed package matched, no release data, or the
    lookup failed) — which keeps the conservative name-level meaning.
    """
    if not data or not codename:
        return "possible"
    verdict = "possible"
    for p in data.get("packages") or []:
        name = (p.get("name") or "").strip()
        inst = installed.get(name)
        if not inst:
            continue  # not installed on this host (by source name)
        st = _status_for(p, codename)
        if st is None:
            continue
        status = (st.get("status") or "").lower()
        if status == "released":
            fixed = (st.get("description") or "").strip()
            # Some entries put the version in a dedicated field instead.
            fixed = fixed or (st.get("fixed_version") or "").strip()
            if fixed and version_lt(inst, fixed):
                return "applicable"
            if fixed:
                verdict = "fixed"
        elif status in _VULN_STATUSES:
            return "applicable"
        # not-affected / DNE / ignored / unknown -> leave verdict unchanged
    return verdict


# --------------------------------------------------------------------------- #
# Release-level "not applicable" (#74): conservative, Ubuntu-data-only.
# --------------------------------------------------------------------------- #
# Statuses that, on an *older* release, mean the fix question was settled
# without leaving that release exposed. "ignored" (often: end of life, never
# fixed) and the vulnerable statuses deliberately disqualify.
_SETTLED_STATUSES = {"released", "not-affected", "dne"}


def _kernel_series(v: str) -> tuple[int, int] | None:
    """Upstream major.minor of an Ubuntu kernel version (``5.15.0-203.213`` ->
    ``(5, 15)``), or None when it does not look like one."""
    _epoch, rest = _split_epoch(v.strip())
    head = rest.split("-", 1)[0].split(".")
    if len(head) < 2 or not (head[0].isdigit() and head[1].isdigit()):
        return None
    return int(head[0]), int(head[1])


def release_na_reason(
    data: dict | None, codename: str, installed: dict[str, str]
) -> str | None:
    """Why a CVE that ``classify_cve`` left as ``possible`` cannot apply to
    this release, or None. Only two cases, both read from Ubuntu's own data:

    1. Ubuntu marks an installed package ``not-affected`` on this release.
    2. Kernel only: Ubuntu does not track this release for the CVE at all
       (it predates the release), every release it does track is settled
       (released / not-affected / DNE — no needed, pending, deferred or
       ignored), and the newest released fix is on an older upstream kernel
       series than the one installed here, e.g. fixed in 4.4 / 4.15 while
       this host runs 5.15. The fix was upstream before this branch existed.

    Anything else stays ``possible``. Never consulted for a CVE that version
    data already labels ``applicable`` or ``fixed``. Pure (no I/O).
    """
    if not data or not codename:
        return None
    for p in data.get("packages") or []:
        name = (p.get("name") or "").strip()
        inst = installed.get(name)
        if not inst:
            continue
        st = _status_for(p, codename)
        if st is not None:
            if (st.get("status") or "").lower() == "not-affected":
                desc = (st.get("description") or "").strip()
                return (f"Ubuntu marks {name} not affected on {codename}"
                        + (f" ({desc})" if desc else ""))
            continue
        if not name.startswith("linux"):
            continue
        here = _kernel_series(inst)
        statuses = p.get("statuses") or []
        if here is None or not statuses:
            continue
        newest: tuple[tuple[int, int], str, str] | None = None
        settled = True
        for s in statuses:
            status = (s.get("status") or "").lower()
            if status not in _SETTLED_STATUSES:
                settled = False
                break
            if status != "released":
                continue
            fixed = ((s.get("description") or "").strip()
                     or (s.get("fixed_version") or "").strip())
            series = _kernel_series(fixed) if fixed else None
            if series is None:
                settled = False  # a fix we cannot place: do not guess
                break
            rel = (s.get("release_codename") or s.get("release") or "?")
            if newest is None or series > newest[0]:
                newest = (series, fixed, rel)
        if settled and newest is not None and newest[0] < here:
            return (f"fixed upstream before linux {here[0]}.{here[1]} "
                    f"(newest Ubuntu fix {newest[1]} on {newest[2]}); "
                    f"{codename} not tracked for this CVE")
    return None
