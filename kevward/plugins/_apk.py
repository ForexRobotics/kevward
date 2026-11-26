# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Reusable base for apk-managed hosts (Alpine Linux, #2).

The apk counterpart of ``_apt.py``, with the same shape and contract:

* ``check`` lists pending upgrades (``apk list --upgradable``; it only reads
  the package index, never changes anything) for the managed packages.
* An upgrade is a **security** update when the Alpine security database
  (secdb.alpinelinux.org, the same data ``apk audit`` tools use) lists a fix
  for the package's origin between the installed and the new version. The
  secdb is fetched once per run, cached on disk and fail-soft: offline, every
  upgrade stays a minor upgrade (never a guessed "security").
* ``apply`` runs ``apk add --upgrade`` for the selected packages: dry-run by
  default, root required, nothing applied unless explicitly allowed.

Every function is a graceful no-op on hosts without ``apk`` (apt hosts are not
affected).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

from ..model import ActionResult, Finding, FindingKind, Severity
from ..plugin import ServicePlugin
from ..util import have, is_root, pkg_needs_reboot, run, run_stream

SECDB_URL = "https://secdb.alpinelinux.org/{branch}/{repo}.json"
SECDB_REPOS = ("main", "community")
SYSTEM_CACHE_DIR = Path("/var/cache/kevward")
CACHE_TTL = 12 * 3600
ALPINE_RELEASE = "/etc/alpine-release"
INSTALL_TIMEOUT_S = 3600

# "name-1.2.3_rc1-r4": the version starts at the last "-<digit>" before "-rN".
_NAMEVER = re.compile(r"^(?P<name>.+?)-(?P<ver>\d[^-\s]*-r\d+)$")
# `apk list --upgradable` (apk-tools >= 2.12):
#   musl-1.2.4-r3 x86_64 {musl} (MIT) [upgradable from: musl-1.2.4-r2]
_UPGRADABLE = re.compile(
    r"^(?P<new>\S+)\s+\S+\s+\{(?P<origin>[^}]*)\}.*\[upgradable from:\s*(?P<cur>\S+)\]"
)


def split_namever(s: str) -> tuple[str, str] | None:
    """'py3-foo-1.0_rc2-r3' -> ('py3-foo', '1.0_rc2-r3'). Pure."""
    m = _NAMEVER.match(s.strip())
    return (m.group("name"), m.group("ver")) if m else None


# --------------------------------------------------------------------------- #
# Alpine version ordering (apk-tools' rules, the parts real packages use)
# --------------------------------------------------------------------------- #
_SUFFIX_RANK = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
                "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_VER = re.compile(
    r"^(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z]?)"
    r"(?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)"
    r"(?:~[0-9a-f]+)?(?:-r(?P<rev>\d+))?$"
)


def _vkey(v: str) -> tuple | None:
    m = _VER.match(v.strip())
    if not m:
        return None
    nums = tuple(int(n) for n in m.group("nums").split("."))
    sufs = tuple((_SUFFIX_RANK[s.rstrip("0123456789")], int(re.sub(r"\D", "", s) or 0))
                 for s in re.findall(r"_([a-z]+\d*)", m.group("suffixes")))
    return nums, m.group("letter"), sufs, int(m.group("rev") or 0)


def _cmp_tuple(a: tuple, b: tuple) -> int:
    return (a > b) - (a < b)


def apk_compare(a: str, b: str) -> int:
    """-1 / 0 / 1 like ``apk version -t``. Pure.

    Numbers compare component-wise (1.10 > 1.9), then the letter, then the
    suffixes (``_alpha`` < ``_beta`` < ``_pre`` < ``_rc`` < none < ``_p``), then
    the ``-rN`` package revision. Unparseable versions fall back to a plain
    string comparison."""
    ka, kb = _vkey(a), _vkey(b)
    if ka is None or kb is None:
        return (a > b) - (a < b)
    for x, y in ((ka[0], kb[0]), (ka[1], kb[1])):
        c = _cmp_tuple(x, y)
        if c:
            return c
    sa, sb = list(ka[2]), list(kb[2])
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (0, 0)       # no suffix sits between rc and p
        y = sb[i] if i < len(sb) else (0, 0)
        c = _cmp_tuple(x, y)
        if c:
            return c
    return _cmp_tuple(ka[3], kb[3])


# --------------------------------------------------------------------------- #
# Pending upgrades
# --------------------------------------------------------------------------- #
def parse_upgradable(text: str) -> list[dict]:
    """``apk list --upgradable`` -> [{pkg, cur, new, origin, security}]. Pure."""
    out: list[dict] = []
    for line in (text or "").splitlines():
        m = _UPGRADABLE.match(line.strip())
        if not m:
            continue
        new, cur = split_namever(m.group("new")), split_namever(m.group("cur"))
        if not new or not cur:
            continue
        out.append({"pkg": new[0], "cur": cur[1], "new": new[1],
                    "origin": m.group("origin") or new[0], "security": False,
                    "cves": [], "kept_back": False})
    return out


def parse_version_list(text: str) -> list[dict]:
    """Older apk-tools: ``apk version -l '<'`` lines like
    ``musl-1.2.4-r2  < 1.2.4-r3``. The origin is not shown, so the package
    name stands in for it. Pure."""
    out: list[dict] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1] != "<":
            continue
        cur = split_namever(parts[0])
        if cur:
            out.append({"pkg": cur[0], "cur": cur[1], "new": parts[2],
                        "origin": cur[0], "security": False, "cves": [],
                        "kept_back": False})
    return out


def parse_secdb(data: object) -> dict[str, dict[str, list[str]]]:
    """secdb JSON -> {origin: {fixed version: [CVE, ...]}}. Pure."""
    out: dict[str, dict[str, list[str]]] = {}
    if not isinstance(data, dict):
        return out
    for item in data.get("packages") or []:
        pkg = (item or {}).get("pkg") or {}
        name, fixes = pkg.get("name"), pkg.get("secfixes")
        if not isinstance(name, str) or not isinstance(fixes, dict):
            continue
        dst = out.setdefault(name, {})
        for ver, ids in fixes.items():
            if isinstance(ver, str):
                dst.setdefault(ver, []).extend(
                    i.split()[0] for i in (ids or []) if isinstance(i, str) and i.strip())
    return out


def classify_changes(changes: list[dict],
                     secdb: dict[str, dict[str, list[str]]]) -> list[dict]:
    """Mark changes whose upgrade crosses a secdb fix. Mutates and returns
    ``changes``. Pure."""
    for c in changes:
        fixes = secdb.get(c["origin"]) or secdb.get(c["pkg"]) or {}
        cves: list[str] = []
        for fixed, ids in fixes.items():
            if apk_compare(c["cur"], fixed) < 0 <= apk_compare(c["new"], fixed):
                cves.extend(ids or [f"fix in {fixed}"])
        if cves:
            c["security"] = True
            c["cves"] = sorted(set(cves))
    return changes


def alpine_branch(release_file: str = ALPINE_RELEASE) -> str | None:
    """'3.19.1' -> 'v3.19'; 'edge' for a ``_alpha``/``_git`` snapshot; None
    when not Alpine."""
    try:
        with open(release_file) as fh:
            rel = fh.read().strip()
    except OSError:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.\d+$", rel)
    return f"v{m.group(1)}.{m.group(2)}" if m else "edge"


def _cache_file(branch: str, repo: str) -> Path:
    name = f"alpine-secdb-{branch}-{repo}.json"
    sys_file = SYSTEM_CACHE_DIR / name
    if os.access(SYSTEM_CACHE_DIR, os.W_OK) or sys_file.is_file():
        return sys_file
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kevward" / name


@lru_cache(maxsize=8)
def fetch_secdb(branch: str, timeout: float = 10.0) -> dict[str, dict[str, list[str]]]:
    """The secdb for one branch (main + community), cached 12h on disk, once
    per process. Offline: a stale cache, else empty (nothing is "security")."""
    merged: dict[str, dict[str, list[str]]] = {}
    if not re.match(r"^(v\d+\.\d+|edge)$", branch or ""):
        return merged
    for repo in SECDB_REPOS:
        cf = _cache_file(branch, repo)
        raw = None
        try:
            if cf.is_file() and time.time() - cf.stat().st_mtime < CACHE_TTL:
                raw = json.loads(cf.read_text())
        except (OSError, ValueError):
            raw = None
        if raw is None:
            try:
                req = urllib.request.Request(SECDB_URL.format(branch=branch, repo=repo),
                                             headers={"User-Agent": "kevward"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    raw = json.loads(resp.read().decode())
                try:
                    cf.parent.mkdir(parents=True, exist_ok=True)
                    cf.write_text(json.dumps(raw))
                except OSError:
                    pass
            except Exception:
                try:
                    raw = json.loads(cf.read_text())
                except (OSError, ValueError):
                    raw = None
        for name, fixes in parse_secdb(raw).items():
            merged.setdefault(name, {}).update(fixes)
    return merged


#: Result of the last ``apk update``: {"state": "ok"|"failed"|"skipped", ...}.
REFRESH: dict | None = None
_SIM: list[dict] | None = None


def reset_simulation() -> None:
    global REFRESH, _SIM
    REFRESH, _SIM = None, None


def refresh_index() -> dict:
    """``apk update`` (root only; it writes the index cache). Never raises."""
    if not is_root():
        return {"state": "skipped", "error": "not root"}
    r = run(["apk", "update", "--quiet"], timeout=180)
    if r.ok:
        return {"state": "ok", "error": ""}
    first = next((ln for ln in (r.err or r.out or "").splitlines() if ln.strip()),
                 f"exit {r.rc}")
    return {"state": "failed", "error": first[:300]}


def pending_upgrades(fetch=fetch_secdb) -> list[dict]:
    """Pending upgrades host-wide, classified; computed once per run and
    shared by every apk plugin. Empty without apk."""
    global REFRESH, _SIM
    if _SIM is not None:
        return [dict(c) for c in _SIM]
    if not have("apk"):
        return []
    REFRESH = refresh_index()
    r = run(["apk", "list", "--upgradable"], timeout=120)
    changes = parse_upgradable(r.out) if r.ok else []
    if not r.ok:  # apk-tools < 2.12 has no `apk list`
        changes = parse_version_list(run(["apk", "version", "-l", "<"], timeout=120).out)
    branch = alpine_branch()
    if changes and branch:
        classify_changes(changes, fetch(branch))
    _SIM = changes
    return [dict(c) for c in _SIM]


def change_needs_reboot(pkg: str) -> bool:
    return pkg_needs_reboot(pkg) or pkg.startswith("linux-") and not pkg.startswith(
        ("linux-headers", "linux-firmware-", "linux-pam"))


def change_finding(service: str, change: dict, branch: str | None = None) -> Finding:
    """One Finding per planned upgrade, same shape as the apt path."""
    security = change["security"]
    title = f"{change['pkg']} {change['cur']} → {change['new']}"
    detail = f"origin package: {change['origin']}"
    url = None
    if security:
        shown = ", ".join(change["cves"][:8]) + (" …" if len(change["cves"]) > 8 else "")
        detail += f"; fixes {shown} (Alpine secdb)"
        url = f"https://security.alpinelinux.org/srcpkg/{change['origin']}"
    reboot = change_needs_reboot(change["pkg"])
    return Finding(
        service=service,
        kind=FindingKind.SECURITY_UPDATE if security else FindingKind.MINOR_UPGRADE,
        severity=Severity.HIGH if security else Severity.LOW,
        title=title,
        detail=detail,
        current_version=change["cur"],
        fixed_version=change["new"],
        reboot_required=reboot,
        ref=change["pkg"],
        url=url,
        origin=f"Alpine {branch}" if branch else None,
        source_package=change["origin"],
    )


def change_findings(service: str, changes: list[dict]) -> list[Finding]:
    branch = alpine_branch()
    return [change_finding(service, c, branch) for c in changes]


def parse_installed(text: str) -> dict[str, str]:
    """``apk list --installed`` -> {name: version}. Pure."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        first = line.split(" ", 1)[0]
        nv = split_namever(first) if "[installed]" in line else None
        if nv:
            out[nv[0]] = nv[1]
    return out


@lru_cache(maxsize=1)
def _installed() -> dict[str, str]:
    if not have("apk"):
        return {}
    r = run(["apk", "list", "--installed"], timeout=60)
    return parse_installed(r.out) if r.ok else {}


def failure_summary(rc: int, timeout_s: int) -> str:
    """First line shown for a failed ``apk add --upgrade``. Pure."""
    if rc == 124:
        return f"apk timed out after {timeout_s}s and was stopped; run `sudo apk fix`"
    return f"apk failed (exit {rc}); check the output, then `sudo apk fix` if needed"


class ApkServicePlugin(ServicePlugin):
    #: apk package names this plugin owns.
    packages: list[str] = []
    #: OpenRC service to flag for restart (informational).
    service_unit: str | None = None

    def detect(self) -> bool:
        inst = _installed()
        return any(p in inst for p in self.packages)

    def version(self) -> str | None:
        inst = _installed()
        for p in self.packages:
            if p in inst:
                return f"{p} {inst[p]}"
        return None

    def check(self) -> list[Finding]:
        owned = set(self.packages)
        return change_findings(self.name, [c for c in pending_upgrades() if c["pkg"] in owned])

    def apply(self, findings: list[Finding], dry_run: bool) -> list[ActionResult]:
        pkgs = sorted({p for f in findings for p in f.refs})
        if not pkgs:
            return []
        desc = "upgrade: " + ", ".join(pkgs)
        if dry_run:
            return [ActionResult(self.name, desc, changed=False, dry_run=True)]
        if not is_root():
            return [ActionResult(self.name, desc, changed=False, ok=False,
                                 output="requires root -- re-run with sudo")]
        if not have("apk"):
            return [ActionResult(self.name, desc, ok=False, output="apk missing")]
        reboot = any(f.reboot_required for f in findings)
        # --upgrade only upgrades what is already installed; --no-interactive
        # never waits on a prompt nobody can see.
        res = run_stream(["apk", "add", "--upgrade", "--no-interactive", *pkgs],
                         timeout=INSTALL_TIMEOUT_S, prefix=f"  [{self.name}] ")
        if res.ok:
            return [ActionResult(self.name, desc, changed=True, ok=True,
                                 output=res.out[-2000:], reboot_required=reboot)]
        return [ActionResult(self.name, desc, changed=False, ok=False,
                             output=failure_summary(res.rc, INSTALL_TIMEOUT_S) + "\n"
                             + (res.err or res.out)[-2000:],
                             reboot_required=reboot)]
