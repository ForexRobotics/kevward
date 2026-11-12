# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.
# ruff: noqa: E501  (fixtures are verbatim apt-get / dpkg-query output)

"""apt findings are grouped by source package (#143). Pure; no host/root."""

from __future__ import annotations

from kevward.model import Finding, FindingKind, Severity
from kevward.plugin import claim_packages
from kevward.plugins import _apt

# hokaku (jammy) on 2026-11-13: USN-9065-1 (glibc) plus an unrelated update.
UPGRADE = """\
Inst libc6-dev [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libc-dev-bin [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libc-devtools [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst locales [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [all])
Inst libc6 [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libc-bin [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst distro-info-data [0.52ubuntu0.9] (0.52ubuntu0.10 Ubuntu:22.04/jammy-updates [all])
"""

DPKG = """\
libc6-dev\tglibc
libc-dev-bin\tglibc
libc-devtools\tglibc
locales\tglibc
libc6:amd64\tglibc
libc-bin\tglibc
distro-info-data\t
"""


def _grouped():
    changes = _apt.parse_inst(UPGRADE)
    src = _apt.parse_source_map(DPKG, [c["pkg"] for c in changes])
    return _apt.group_findings(changes, "apt", src, "jammy")


def test_parse_source_map_handles_empty_source_and_multiarch():
    m = _apt.parse_source_map(DPKG, ["libc6", "distro-info-data", "unknown-pkg"])
    assert m == {"libc6": "glibc", "distro-info-data": "distro-info-data", "unknown-pkg": "unknown-pkg"}


def test_glibc_is_one_high_finding_with_all_packages():
    fs = _grouped()
    assert len(fs) == 2
    glibc = next(f for f in fs if f.title.startswith("glibc"))
    assert glibc.severity == Severity.HIGH
    assert glibc.kind == FindingKind.SECURITY_UPDATE
    assert glibc.title == "glibc 2.35-0ubuntu3.15 → 2.35-0ubuntu3.18 (6 packages)"
    assert sorted(glibc.packages) == sorted(
        ["libc6-dev", "libc-dev-bin", "libc-devtools", "locales", "libc6", "libc-bin"]
    )
    assert glibc.reboot_required  # libc6 implies a reboot
    assert glibc.url == "https://ubuntu.com/security/notices?release=jammy&details=glibc"
    assert glibc.to_dict()["packages"] == glibc.packages


def test_single_package_keeps_old_shape():
    fs = _grouped()
    other = next(f for f in fs if f.ref == "distro-info-data")
    assert other.title == "distro-info-data 0.52ubuntu0.9 → 0.52ubuntu0.10"
    assert other.packages == []
    assert other.severity == Severity.LOW
    assert other.url is None  # not a security update


def test_security_and_minor_from_one_source_stay_separate():
    text = (
        "Inst a1 [1] (2 Ubuntu:22.04/jammy-security [amd64])\n"
        "Inst a2 [1] (2 Ubuntu:22.04/jammy-updates [amd64])\n"
    )
    changes = _apt.parse_inst(text)
    fs = _apt.group_findings(changes, "apt", {"a1": "a", "a2": "a"}, "jammy")
    assert sorted(f.kind for f in fs) == sorted([FindingKind.SECURITY_UPDATE, FindingKind.MINOR_UPGRADE])


def _f(pkgs, ref=None):
    return Finding("x", FindingKind.SECURITY_UPDATE, Severity.HIGH, "t",
                   ref=ref or pkgs[0], packages=pkgs if len(pkgs) > 1 else [])


def test_claiming_trims_grouped_findings():
    claimed: set[str] = set()
    # e.g. the apache plugin claims apache2 + apache2-bin first ...
    first = claim_packages([_f(["apache2", "apache2-bin"])], claimed)
    assert [f.refs for f in first] == [["apache2", "apache2-bin"]]
    # ... then the host-wide apt group for the same source only keeps the rest.
    second = claim_packages([_f(["apache2", "apache2-bin", "apache2-data", "apache2-utils"])], claimed)
    assert [f.refs for f in second] == [["apache2-data", "apache2-utils"]]
    # a fully claimed finding disappears
    assert claim_packages([_f(["apache2"])], claimed) == []


def test_apply_installs_every_grouped_package(monkeypatch):
    monkeypatch.setattr(_apt, "is_root", lambda: False)

    class P(_apt.AptServicePlugin):
        name = "p"

    res = P().apply([_f(["libc6", "libc-bin", "locales"])], dry_run=True)
    assert res[0].description == "install: libc-bin, libc6, locales"
