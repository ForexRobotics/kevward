# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.
# ruff: noqa: E501  (fixtures are verbatim apt-get / dpkg-query output)

"""#174: an apt finding says which packages are still old and which of the
same source are already upgraded. Pure; no host/root."""

from __future__ import annotations

from kevward.engine import RunResult
from kevward.model import ServiceReport
from kevward.plugins import _apt
from kevward.reporting.html import render

OLD = "8.3.36-1+ubuntu22.04.1+deb.sury.org+1"
NEW = "8.3.37-2+ubuntu22.04.1+deb.sury.org+1"

# hokaku on 2026-11-21: `apt-get install --only-upgrade 'php8.3-*'` the day
# before upgraded everything but the php8.3 metapackage.
SIM = f"Inst php8.3 [{OLD}] ({NEW} LP-PPA-ondrej-php:22.04/jammy [all])\n"

INSTALLED = "\n".join([
    f"php8.3\t\t{OLD}\tii ",
    f"php8.3-fpm\tphp8.3\t{NEW}\tii ",
    f"php8.3-cli\tphp8.3\t{NEW}\tii ",
    f"php8.3-common\tphp8.3\t{NEW}\tii ",
    f"php8.3-gone\tphp8.3\t{NEW}\trc ",
    f"libapache2-mod-php8.3:amd64\tphp8.3\t{NEW}\tii ",
    "nginx\t\t1.18.0-6ubuntu14.24\tii ",
    "garbage line",
])


def _finding(sec=True):
    changes = _apt.parse_inst(SIM)
    changes[0]["security"] = sec
    src = {"php8.3": "php8.3"}
    [f] = _apt.group_findings(changes, "php", src, "jammy",
                              _apt.parse_installed(INSTALLED))
    return f


def test_parse_installed():
    inst = _apt.parse_installed(INSTALLED)
    assert ("php8.3", OLD) in inst["php8.3"]
    assert ("libapache2-mod-php8.3", NEW) in inst["php8.3"]
    assert all(p != "php8.3-gone" for p, _ in inst["php8.3"])  # not installed (rc)
    assert inst["nginx"] == [("nginx", "1.18.0-6ubuntu14.24")]


def test_single_metapackage_left_behind():
    f = _finding()
    assert f.source_package == "php8.3"
    assert f.package_versions == {"php8.3": OLD}
    assert f.updated_packages == ["libapache2-mod-php8.3", "php8.3-cli",
                                  "php8.3-common", "php8.3-fpm"]
    d = f.to_dict()
    assert d["package_versions"] == {"php8.3": OLD}
    assert len(d["updated_packages"]) == 4


def test_html_names_old_package_and_upgraded_siblings():
    r = RunResult(host="hokaku", generated_at="2026-11-21T00:00:00+00:00", os="Ubuntu 22.04")
    r.services.append(ServiceReport(service="php", present=True, findings=[_finding()]))
    html = render(r)
    assert f"still old: php8.3 {OLD}" in html
    assert f"4 other php8.3 packages already at {NEW}" in html
    assert "php8.3-fpm" in html


def test_grouped_findings_list_each_version():
    upgrade = ("Inst libc6 [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-security [amd64])\n"
               "Inst libc-bin [2.35-0ubuntu3.15] (2.35-0ubuntu3.18 Ubuntu:22.04/jammy-security [amd64])\n")
    changes = _apt.parse_inst(upgrade)
    [f] = _apt.group_findings(changes, "apt", {"libc6": "glibc", "libc-bin": "glibc"}, "jammy")
    assert f.package_versions == {"libc6": "2.35-0ubuntu3.15", "libc-bin": "2.35-0ubuntu3.15"}
    assert f.updated_packages == []  # no installed data: nothing claimed
    r = RunResult(host="h", generated_at="2026-11-21T00:00:00+00:00", os="Ubuntu 22.04")
    r.services.append(ServiceReport(service="apt", present=True, findings=[f]))
    html = render(r)
    assert "still old: libc6 2.35-0ubuntu3.15, libc-bin 2.35-0ubuntu3.15" in html
    assert "already at" not in html
