# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Reusable base for apt-managed services.

Most Ubuntu services (nginx, php, openssh, ufw, ...) are just a set of apt
packages. This base turns "which packages" into check/apply behaviour:

* ``check`` surfaces pending security updates and (separately) minor upgrades
  for the managed packages, using ``apt-get -s`` (simulate) so it never
  changes anything.
* ``apply`` installs the selected packages, honouring dry-run.

Concrete plugins typically only declare ``name``, ``packages`` and
``service_unit``.
"""

from __future__ import annotations

import contextlib
import fnmatch
import os
import re
from dataclasses import dataclass, field, replace

from ..model import ActionResult, Finding, FindingKind, Severity
from ..plugin import ServicePlugin
from ..util import have, is_root, pkg_needs_reboot, run, run_stream


@dataclass
class AptSettings:
    """``[apt]`` config, set once per run by the engine (``configure``)."""

    # apt origins whose updates count as security updates (#169), matched as
    # globs against the origin name (the part before ":"), e.g.
    # "LP-PPA-ondrej-php". Empty by default: nothing changes silently.
    security_origins: list[str] = field(default_factory=list)
    # Ask php.net whether a pending PHP upgrade is a security release (#169).
    php_release_check: bool = True
    # Wall-clock limit for `apt-get install` in apply (#170); 0 = no limit.
    install_timeout_s: int = 3600


SETTINGS = AptSettings()


def configure(settings: AptSettings) -> None:
    global SETTINGS
    SETTINGS = settings

# Lines from `apt-get -s upgrade` look like:
#   Inst nginx [1.24.0-1] (1.24.0-2ubuntu1 Ubuntu:24.04/noble-security [amd64])
_INST = re.compile(
    r"^Inst\s+(?P<pkg>\S+)\s+\[(?P<cur>[^\]]+)\]\s+\((?P<new>\S+)\s+(?P<origin>[^)]*)\)"
)


def _pkg_version(pkg: str) -> str | None:
    res = run(["dpkg-query", "-W", "-f=${Version}", pkg])
    return res.out.strip() or None if res.ok else None


def parse_inst(text: str) -> list[dict]:
    """Planned upgrades of *installed* packages from ``apt-get -s`` output.

    Only ``Inst`` lines with a ``[current]`` version are returned: packages
    that would be newly installed (e.g. a new ``linux-image-X.Y.Z``) have no
    current version and are represented by the metapackage that pulls them in.
    """
    out: list[dict] = []
    for line in text.splitlines():
        m = _INST.match(line.strip())
        if m:
            d = m.groupdict()
            d["security"] = "security" in d["origin"].lower()
            d["kept_back"] = False
            out.append(d)
    return out


def origin_names(origin: str) -> list[str]:
    """'Ubuntu:22.04/jammy-updates, LP-PPA-ondrej-php:22.04/jammy [amd64]'
    -> ['Ubuntu', 'LP-PPA-ondrej-php']. Pure."""
    text = re.sub(r"\s*\[[^\]]*\]\s*$", "", origin or "")
    return [part.strip().split(":", 1)[0] for part in text.split(",") if part.strip()]


def clean_origin(origin: str) -> str:
    """Origin without the trailing ``[arch]``. Pure."""
    return re.sub(r"\s*\[[^\]]*\]\s*$", "", origin or "").strip()


def classify_changes(changes: list[dict], security_origins: list[str],
                     php_check: bool, php_fetch=None) -> list[dict]:
    """Second pass over ``parse_inst`` results (#169).

    ``parse_inst`` treats only origins containing "security" (Ubuntu's
    -security pockets) as security. Here, updates from an origin listed in
    ``[apt] security_origins`` become security updates, and pending PHP
    upgrades are checked against php.net's security releases. Mutates and
    returns ``changes``.
    """
    pats = [p for p in security_origins if p]
    for c in changes:
        if c["security"] or not pats:
            continue
        names = origin_names(c["origin"])
        hit = next((p for p in pats for n in names if fnmatch.fnmatchcase(n, p)), None)
        if hit:
            c["security"] = True
            c["security_why"] = (f"origin {names[0]} matches [apt] security_origins "
                                 f"({hit!r})")
    if php_check:
        from ..integrations import php_releases

        php_releases.classify(changes, **({"fetch": php_fetch} if php_fetch else {}))
    return changes


def merge_kept_back(upgrade: list[dict], full: list[dict]) -> list[dict]:
    """Add upgrades that ``apt-get upgrade`` keeps back but a full upgrade does.

    ``apt-get upgrade`` never installs new packages, so a kernel update (the
    ``linux-generic`` / ``linux-image-generic`` metapackages pulling in a new
    ``linux-image-*``) is silently "kept back" and never shows up as ``Inst``.
    Diffing against ``apt-get -s dist-upgrade`` recovers those, flagged
    ``kept_back`` (locale-independent: no parsing of translated headers).
    Phased-update deferrals are honoured by both commands, so they stay out.
    """
    seen = {c["pkg"] for c in upgrade}
    extra = []
    for c in full:
        if c["pkg"] not in seen:
            c = dict(c, kept_back=True)
            extra.append(c)
    return upgrade + extra


#: Result of the last ``apt-get update`` (#171): {"state": "ok" | "failed" |
#: "skipped", "seconds": float, "error": str}. None until a simulation ran.
REFRESH: dict | None = None
_SIM: list[dict] | None = None


def reset_simulation() -> None:
    """Forget the cached plan; the engine calls this once per run."""
    global REFRESH, _SIM
    REFRESH, _SIM = None, None


APT_LISTS = "/var/lib/apt/lists"


#: Written by apt-daily (APT::Periodic) after each successful `apt-get update`.
APT_SUCCESS_STAMP = "/var/lib/apt/periodic/update-success-stamp"


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def lists_updated_at(lists_dir: str = APT_LISTS,
                     stamp: str = APT_SUCCESS_STAMP) -> str | None:
    """When the package lists were last refreshed by someone else (#179): the
    apt-daily success stamp, or the newest ``*Release`` file. apt gives those
    the repository's Last-Modified time, so they can be older than the actual
    refresh; after kevward's own successful refresh the current time is used
    instead. ISO 8601 UTC, None if unknown."""
    import glob
    from datetime import datetime, timezone

    newest = 0.0
    with contextlib.suppress(OSError):
        newest = os.path.getmtime(stamp)
    for path in glob.glob(os.path.join(lists_dir, "*Release")):
        try:
            newest = max(newest, os.path.getmtime(path))
        except OSError:
            continue
    if not newest:
        return None
    return datetime.fromtimestamp(newest, tz=timezone.utc).isoformat(timespec="seconds")


#: apt-get update writes temporary files (apt-key's config, #231) to $TMPDIR.
#: The report service keeps /tmp read-only (ProtectSystem=strict), so point
#: apt at kevward's own writable cache instead of opening up /tmp.
APT_TMPDIR = "/var/cache/kevward/tmp"


def _apt_tmpdir(path: str = APT_TMPDIR, sandbox_user: str = "_apt") -> str | None:
    """A writable TMPDIR for apt, or None to leave apt's default.

    apt's download and gpgv methods run as the sandbox user ``_apt`` and fall
    back to /tmp when $TMPDIR is not writable for them, so the directory is
    owned by ``_apt`` (0700). Without that user, a sticky 1777 directory like
    /tmp itself."""
    import pwd

    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            uid = pwd.getpwnam(sandbox_user).pw_uid
        except KeyError:
            os.chmod(path, 0o1777)
        else:
            os.chown(path, uid, 0)
            os.chmod(path, 0o700)
        return path
    except OSError:
        return None


def _first_error(text: str, rc: int) -> str:
    """The most useful line of apt's output: an ``E:`` line, else the first."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    for ln in lines:
        if ln.startswith("E:"):
            return ln[:300]
    return (lines[0] if lines else f"exit {rc}")[:300]


def refresh_lists() -> dict:
    """``apt-get update`` and how it went, plus when the lists were last
    refreshed (by this run or anything else). Skipped without root, where it
    could not write the lists anyway. Never raises."""
    import time

    if not is_root():
        return {"state": "skipped", "seconds": 0.0, "error": "not root",
                "lists_updated_at": lists_updated_at()}
    t0 = time.monotonic()
    tmp = _apt_tmpdir()
    r = run(["apt-get", "update", "-qq"], timeout=180,
            env={"TMPDIR": tmp} if tmp else None)
    secs = round(time.monotonic() - t0, 1)
    if r.ok:
        return {"state": "ok", "seconds": secs, "error": "",
                "lists_updated_at": _now_iso()}
    first = _first_error((r.err or "") + "\n" + (r.out or ""), r.rc)
    return {"state": "failed", "seconds": secs, "error": first,
            "lists_updated_at": lists_updated_at()}


def _simulate_upgrade() -> list[dict]:
    """Planned changes from a simulated upgrade, including kept-back ones.

    Computed once per run and shared by every apt plugin (it used to run
    ``apt-get update`` once per plugin). The refresh result is kept in
    ``REFRESH`` so ``apply`` can say whether the plan is current (#171).
    """
    global REFRESH, _SIM
    if _SIM is not None:
        return [dict(c) for c in _SIM]
    REFRESH = refresh_lists()
    upgrade = parse_inst(run(["apt-get", "-s", "upgrade"], timeout=180).out)
    full = parse_inst(run(["apt-get", "-s", "dist-upgrade"], timeout=180).out)
    _SIM = classify_changes(merge_kept_back(upgrade, full),
                            SETTINGS.security_origins, SETTINGS.php_release_check)
    return [dict(c) for c in _SIM]


# Kernel metapackages: upgrading them installs a new kernel image.
_KERNEL_META = re.compile(r"^linux-(generic|virtual|image|signed-image)(-|$)")


def change_needs_reboot(pkg: str) -> bool:
    return pkg_needs_reboot(pkg) or bool(_KERNEL_META.match(pkg))


def change_finding(service: str, change: dict) -> Finding:
    """One Finding for one planned package change (shared by apt plugins)."""
    security = change["security"]
    kept = change.get("kept_back", False)
    title = f"{change['pkg']} {change['cur']} → {change['new']}"
    detail = f"origin: {clean_origin(change['origin'])}"
    if change.get("security_why"):
        detail += f"; security update because {change['security_why']}"
    elif change.get("security_unchecked"):
        detail += f"; {change['security_unchecked']}"
    if kept:
        title += " (kept back)"
        detail += (
            "; `apt-get upgrade` keeps this back because it needs new packages "
            "(typically a new kernel). Apply with "
            f"`sudo apt-get install {change['pkg']}` or `sudo apt full-upgrade`."
        )
    reboot = change_needs_reboot(change["pkg"])
    if security:
        severity = Severity.HIGH
    elif kept and reboot:
        # A kept-back kernel never lands via `apt upgrade` (nor a typical
        # unattended run), so the host keeps booting the old kernel until
        # someone acts. Not "low", even when it came from -updates.
        severity = Severity.MEDIUM
        detail += "; the new kernel will not be installed until you do this."
    else:
        severity = Severity.LOW
    return Finding(
        service=service,
        kind=FindingKind.SECURITY_UPDATE if security else FindingKind.MINOR_UPGRADE,
        severity=severity,
        title=title,
        detail=detail,
        current_version=change["cur"],
        fixed_version=change["new"],
        # Only the kernel image (incl. its metapackages) and glibc imply a reboot.
        reboot_required=reboot,
        ref=change["pkg"],
        url=change.get("url"),
        origin=clean_origin(change["origin"]) or None,
    )


def source_packages(pkgs: list[str]) -> dict[str, str]:
    """Binary package -> source package for the given installed packages.

    ``${source:Package}`` is empty when the source has the binary's name, so
    that falls back to the binary name. Packages dpkg doesn't know map to
    themselves.
    """
    if not pkgs or not have("dpkg-query"):
        return {p: p for p in pkgs}
    r = run(["dpkg-query", "-W", "-f=${Package}\\t${source:Package}\\n", *pkgs])
    return parse_source_map(r.out, pkgs)


def parse_source_map(text: str, pkgs: list[str]) -> dict[str, str]:
    """Parse ``dpkg-query -W -f='${Package}\\t${source:Package}\\n'``. Pure."""
    out = {p: p for p in pkgs}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        pkg, src = parts[0].strip().split(":", 1)[0], parts[1].strip()
        if pkg in out and src:
            out[pkg] = src
    return out


def parse_installed(text: str) -> dict[str, list[tuple[str, str]]]:
    """Source package -> [(binary, version)] of installed packages, from
    ``dpkg-query -W -f='${Package}\\t${source:Package}\\t${Version}\\t${db:Status-Abbrev}\\n'``.
    Only fully installed (``ii``) packages count. Pure."""
    out: dict[str, list[tuple[str, str]]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not parts[3].startswith("ii"):
            continue
        pkg = parts[0].strip().split(":", 1)[0]
        src = parts[1].strip() or pkg
        out.setdefault(src, []).append((pkg, parts[2].strip()))
    return out


def installed_by_source() -> dict[str, list[tuple[str, str]]]:
    """All installed packages grouped by source (one dpkg-query, #174)."""
    if not have("dpkg-query"):
        return {}
    r = run(["dpkg-query", "-W",
             "-f=${Package}\t${source:Package}\t${Version}\t${db:Status-Abbrev}\n"])
    return parse_installed(r.out) if r.ok else {}


def notices_url(source: str, codename: str) -> str | None:
    """Ubuntu Security Notices for this source package and release."""
    if not codename:
        return None
    return (
        "https://ubuntu.com/security/notices"
        f"?release={codename}&details={source}"
    )


def _with_versions(f: Finding, src: str, members: list[dict],
                   installed: dict[str, list[tuple[str, str]]]) -> Finding:
    """Add #174's per-package versions and already-updated siblings."""
    pkgs = {c["pkg"] for c in members}
    new = {c["new"] for c in members}
    updated = sorted(p for p, v in installed.get(src, []) if p not in pkgs and v in new)
    return replace(f, source_package=src,
                   package_versions={c["pkg"]: c["cur"] for c in members},
                   updated_packages=updated)


def group_findings(
    changes: list[dict], service: str, src_map: dict[str, str], codename: str = "",
    installed: dict[str, list[tuple[str, str]]] | None = None,
) -> list[Finding]:
    """One finding per (source package, kind, kept-back) instead of per binary.

    A single advisory such as a glibc update touches several binary packages
    (libc6, libc-bin, locales, ...). Listing each as its own HIGH inflates the
    counts and hides that there is one thing to act on (#143). Grouping keeps
    every package in ``Finding.packages`` so ``apply()`` still installs all of
    them. Pure apart from what the caller passes in.
    """
    groups: dict[tuple, list[dict]] = {}
    for c in changes:
        key = (src_map.get(c["pkg"], c["pkg"]), c["security"], c.get("kept_back", False))
        groups.setdefault(key, []).append(c)

    out: list[Finding] = []
    for (src, security, kept), members in groups.items():
        singles = [change_finding(service, c) for c in members]
        if len(singles) == 1:
            f = singles[0]
            if security and not f.url:
                f = replace(f, url=notices_url(src, codename))
            out.append(_with_versions(f, src, members, installed or {}))
            continue
        worst = max(singles, key=lambda f: f.severity.rank)
        pkgs = [c["pkg"] for c in members]
        cur = {c["cur"] for c in members}
        new = {c["new"] for c in members}
        span = (
            f"{next(iter(cur))} → {next(iter(new))}"
            if len(cur) == 1 and len(new) == 1
            else "→ " + ", ".join(sorted(new))
        )
        origins = sorted({f.origin for f in singles if f.origin})
        own_url = next((c["url"] for c in members if c.get("url")), None)
        title = f"{src} {span} ({len(pkgs)} packages)"
        if kept:
            title += " (kept back)"
        detail = "packages: " + ", ".join(pkgs) + "; " + worst.detail
        out.append(_with_versions(
            Finding(
                service=service,
                kind=worst.kind,
                severity=worst.severity,
                title=title,
                detail=detail,
                current_version=next(iter(cur)) if len(cur) == 1 else None,
                fixed_version=next(iter(new)) if len(new) == 1 else None,
                reboot_required=any(f.reboot_required for f in singles),
                ref=pkgs[0],
                packages=pkgs,
                url=own_url or (notices_url(src, codename) if security else None),
                origin=", ".join(origins) or None,
            ), src, members, installed or {}))
    return out


def change_findings(service: str, changes: list[dict]) -> list[Finding]:
    """Grouped findings for planned changes (looks up source packages)."""
    if not changes:
        return []
    from ..integrations.usn import host_codename

    src_map = source_packages(sorted({c["pkg"] for c in changes}))
    return group_findings(changes, service, src_map, host_codename(),
                          installed_by_source())


class AptServicePlugin(ServicePlugin):
    #: apt package names this plugin owns.
    packages: list[str] = []
    #: systemd unit to flag for restart (informational).
    service_unit: str | None = None

    def detect(self) -> bool:
        return any(_pkg_version(p) for p in self.packages)

    def version(self) -> str | None:
        for p in self.packages:
            v = _pkg_version(p)
            if v:
                return f"{p} {v}"
        return None

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        owned = set(self.packages)
        mine = [c for c in _simulate_upgrade() if c["pkg"] in owned]
        findings.extend(change_findings(self.name, mine))
        return findings

    def apply(self, findings: list[Finding], dry_run: bool) -> list[ActionResult]:
        pkgs = sorted({p for f in findings for p in f.refs})
        if not pkgs:
            return []
        desc = "install: " + ", ".join(pkgs)
        if dry_run:
            return [ActionResult(self.name, desc, changed=False, dry_run=True)]
        if not is_root():
            return [
                ActionResult(
                    self.name, desc, changed=False, ok=False,
                    output="requires root -- re-run with sudo",
                )
            ]
        if not have("apt-get"):
            return [ActionResult(self.name, desc, ok=False, output="apt-get missing")]
        # --only-upgrade never installs the *named* packages afresh, but still
        # pulls in new dependencies (e.g. the new kernel for a kept-back
        # linux-generic).
        # Non-interactive like unattended-upgrades: keep locally modified
        # conffiles instead of waiting on a prompt nobody can see (#170).
        args = ["apt-get", "install", "-y", "--only-upgrade",
                "-o", "Dpkg::Options::=--force-confdef",
                "-o", "Dpkg::Options::=--force-confold", *pkgs]
        reboot = any(f.reboot_required for f in findings)
        print(f"[{self.name}] running apt-get install for {len(pkgs)} package(s); "
              "a kernel can take several minutes...", flush=True)
        res = run_stream(args, timeout=SETTINGS.install_timeout_s or None,
                         env={"DEBIAN_FRONTEND": "noninteractive"},
                         prefix=f"  [{self.name}] ")
        if res.ok:
            return [ActionResult(self.name, desc, changed=True, ok=True,
                                 output=res.out[-2000:], reboot_required=reboot)]
        audit = run(["dpkg", "--audit"], timeout=60)
        summary = failure_summary(res.rc, SETTINGS.install_timeout_s, audit.out,
                                  kernel=any(_KERNEL_META.match(p) for p in pkgs))
        return [ActionResult(self.name, desc, changed=False, ok=False,
                             output=summary + "\n" + (res.err or res.out)[-2000:],
                             reboot_required=reboot)]


def failure_summary(rc: int, timeout_s: int, dpkg_audit: str, kernel: bool) -> str:
    """First line shown for a failed install, with what to do next (#170). Pure.

    ``dpkg_audit`` is the output of ``dpkg --audit``: empty means every
    package is fully installed and configured.
    """
    what = (f"apt-get timed out after {timeout_s}s and was stopped" if rc == 124
            else f"apt-get failed (exit {rc})")
    if dpkg_audit.strip():
        n = sum(1 for ln in dpkg_audit.splitlines() if ln.startswith(" "))
        msg = (f"{what}; dpkg --audit reports unfinished packages"
               f"{f' ({n})' if n else ''}: run `sudo dpkg --configure -a`")
        if kernel:
            msg += " and do not reboot until `dpkg --audit` prints nothing"
        return msg
    return f"{what}; dpkg --audit is clean (no half-installed packages)"
