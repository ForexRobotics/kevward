# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#2: the Alpine apk backend. Fixture text only; no Alpine host or network."""

from __future__ import annotations

import pytest

from kevward.model import FindingKind, Severity
from kevward.plugins import _apk as apk
from kevward.plugins.apk_base import ApkPlugin
from kevward.plugins.openssh_apk import OpensshApkPlugin
from kevward.util import Cmd

UPGRADABLE = """\
musl-1.2.4_git20230717-r5 x86_64 {musl} (MIT) [upgradable from: musl-1.2.4_git20230717-r4]
openssl-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [upgradable from: openssl-3.1.4-r1]
libcrypto3-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [upgradable from: libcrypto3-3.1.4-r1]
openssh-server-9.6_p1-r0 x86_64 {openssh} (SSH-OpenSSH) [upgradable from: openssh-server-9.5_p1-r0]
py3-foo-bar-2.0-r0 noarch {py3-foo-bar} (MIT) [upgradable from: py3-foo-bar-1.9-r1]
linux-lts-6.6.14-r0 x86_64 {linux-lts} (GPL-2.0-only) [upgradable from: linux-lts-6.6.8-r1]
"""

SECDB = {
    "distroversion": "v3.19",
    "packages": [
        {"pkg": {"name": "openssl", "secfixes": {
            "3.1.4-r1": ["CVE-2023-5678"],
            "3.1.4-r3": ["CVE-2023-6129"],
            "3.1.4-r4": ["CVE-2023-6237", "CVE-2024-0727"],
        }}},
        {"pkg": {"name": "openssh", "secfixes": {
            "9.6_p1-r0": ["CVE-2023-48795 GHSA-45x7-px36-x8w8", "CVE-2023-51384"],
            "8.4_p1-r0": ["CVE-2020-15778"],
        }}},
        {"pkg": {"name": "bad"}},
    ],
}


@pytest.mark.parametrize("a, b, want", [
    ("1.2.4-r2", "1.2.4-r3", -1),
    ("1.10-r0", "1.9-r0", 1),
    ("9.5_p1-r0", "9.6_p1-r0", -1),
    ("1.0_rc1-r0", "1.0-r0", -1),
    ("1.0-r0", "1.0_p1-r0", -1),
    ("1.0_alpha-r0", "1.0_beta-r0", -1),
    ("1.2.4_git20230717-r5", "1.2.4_git20230717-r4", 1),
    ("1.0a-r0", "1.0-r0", 1),
    ("3.1.4-r1", "3.1.4-r1", 0),
])
def test_apk_compare(a, b, want):
    assert apk.apk_compare(a, b) == want


def test_split_namever():
    assert apk.split_namever("py3-foo-bar-2.0-r0") == ("py3-foo-bar", "2.0-r0")
    assert apk.split_namever("openssh-server-9.6_p1-r0") == ("openssh-server", "9.6_p1-r0")
    assert apk.split_namever("nonsense") is None


def test_parse_upgradable():
    cs = apk.parse_upgradable(UPGRADABLE + "WARNING: something\n")
    assert [(c["pkg"], c["cur"], c["new"], c["origin"]) for c in cs][:4] == [
        ("musl", "1.2.4_git20230717-r4", "1.2.4_git20230717-r5", "musl"),
        ("openssl", "3.1.4-r1", "3.1.4-r5", "openssl"),
        ("libcrypto3", "3.1.4-r1", "3.1.4-r5", "openssl"),
        ("openssh-server", "9.5_p1-r0", "9.6_p1-r0", "openssh"),
    ]
    assert len(cs) == 6 and not any(c["security"] for c in cs)


def test_parse_version_list():
    cs = apk.parse_version_list("Installed:  Available:\nmusl-1.2.4-r2  < 1.2.4-r3\n"
                                "busybox-1.36.1-r15  = 1.36.1-r15\n")
    assert [(c["pkg"], c["cur"], c["new"]) for c in cs] == [("musl", "1.2.4-r2", "1.2.4-r3")]


def test_classify_with_secdb():
    secdb = apk.parse_secdb(SECDB)
    assert "bad" not in secdb
    assert secdb["openssh"]["9.6_p1-r0"] == ["CVE-2023-48795", "CVE-2023-51384"]
    cs = {c["pkg"]: c for c in apk.classify_changes(apk.parse_upgradable(UPGRADABLE), secdb)}
    # cur r1 is already past the r1 fix; r3 and r4 fixes are crossed
    assert cs["openssl"]["security"] and cs["openssl"]["cves"] == [
        "CVE-2023-6129", "CVE-2023-6237", "CVE-2024-0727"]
    assert cs["libcrypto3"]["security"]                  # matched via its origin
    assert cs["openssh-server"]["cves"] == ["CVE-2023-48795", "CVE-2023-51384"]
    assert not cs["musl"]["security"] and not cs["py3-foo-bar"]["security"]
    # no secdb (offline): nothing is guessed as security
    assert not any(c["security"] for c in apk.classify_changes(
        apk.parse_upgradable(UPGRADABLE), {}))


def test_findings_shape():
    cs = apk.classify_changes(apk.parse_upgradable(UPGRADABLE), apk.parse_secdb(SECDB))
    fs = {f.ref: f for f in (apk.change_finding("apk", c, "v3.19") for c in cs)}
    f = fs["openssh-server"]
    assert (f.kind, f.severity) == (FindingKind.SECURITY_UPDATE, Severity.HIGH)
    assert f.title == "openssh-server 9.5_p1-r0 → 9.6_p1-r0"
    assert "CVE-2023-48795" in f.detail and f.url.endswith("/srcpkg/openssh")
    assert (f.origin, f.source_package) == ("Alpine v3.19", "openssh")
    assert (fs["musl"].kind, fs["musl"].severity) == (FindingKind.MINOR_UPGRADE, Severity.LOW)
    assert fs["linux-lts"].reboot_required and not fs["openssl"].reboot_required


def test_alpine_branch(tmp_path):
    f = tmp_path / "alpine-release"
    f.write_text("3.19.1\n")
    assert apk.alpine_branch(str(f)) == "v3.19"
    f.write_text("3.20_alpha20240329\n")
    assert apk.alpine_branch(str(f)) == "edge"
    assert apk.alpine_branch(str(tmp_path / "missing")) is None


def test_parse_installed():
    text = ("openssh-server-9.6_p1-r0 x86_64 {openssh} (SSH-OpenSSH) [installed]\n"
            "musl-1.2.4-r2 x86_64 {musl} (MIT) [installed]\n"
            "nginx-1.24.0-r15 x86_64 {nginx} (BSD-2-Clause) \n")
    assert apk.parse_installed(text) == {"openssh-server": "9.6_p1-r0", "musl": "1.2.4-r2"}


@pytest.fixture
def alpine(monkeypatch, tmp_path):
    rel = tmp_path / "alpine-release"
    rel.write_text("3.19.1\n")
    monkeypatch.setattr(apk, "ALPINE_RELEASE", str(rel))
    monkeypatch.setattr(apk.alpine_branch, "__defaults__", (str(rel),))
    monkeypatch.setattr(apk, "have", lambda c: c == "apk")
    monkeypatch.setattr("kevward.plugins.apk_base.have", lambda c: c == "apk")
    monkeypatch.setattr(apk, "is_root", lambda: False)
    calls = []

    def fake_run(argv, timeout=0, **k):
        calls.append(argv)
        if argv[:3] == ["apk", "list", "--upgradable"]:
            return Cmd(0, UPGRADABLE, "")
        if argv[:3] == ["apk", "list", "--installed"]:
            return Cmd(0, "openssh-server-9.5_p1-r0 x86_64 {openssh} (X) [installed]\n", "")
        return Cmd(1, "", "unexpected")

    monkeypatch.setattr(apk, "run", fake_run)
    apk.reset_simulation()
    apk._installed.cache_clear()
    monkeypatch.setattr(apk, "fetch_secdb", lambda branch: apk.parse_secdb(SECDB))
    monkeypatch.setattr(apk.pending_upgrades, "__defaults__",
                        (lambda branch: apk.parse_secdb(SECDB),))
    yield calls
    apk.reset_simulation()
    apk._installed.cache_clear()


def test_plugins_on_alpine(alpine):
    host = ApkPlugin()
    assert host.detect() and host.supports_apply
    fs = host.check()
    assert len(fs) == 6 and sum(f.severity is Severity.HIGH for f in fs) == 3
    ssh = OpensshApkPlugin()
    assert ssh.detect() and ssh.version() == "openssh-server 9.5_p1-r0"
    assert [f.ref for f in ssh.check()] == ["openssh-server"]
    assert apk.REFRESH == {"state": "skipped", "error": "not root"}
    # one `apk list --upgradable` shared by both plugins, never a write
    assert sum(c[:3] == ["apk", "list", "--upgradable"] for c in alpine) == 1
    assert not any(c[:2] in (["apk", "add"], ["apk", "update"]) for c in alpine)


def test_apply_is_safe(alpine):
    p = OpensshApkPlugin()
    fs = p.check()
    dry = p.apply(fs, dry_run=True)
    assert dry[0].dry_run and not dry[0].changed and "openssh-server" in dry[0].description
    real = p.apply(fs, dry_run=False)                 # not root in the fixture
    assert not real[0].ok and "requires root" in real[0].output
    assert not any(c[:2] == ["apk", "add"] for c in alpine)


def test_no_apk_is_a_no_op(monkeypatch):
    monkeypatch.setattr(apk, "have", lambda c: False)
    monkeypatch.setattr("kevward.plugins.apk_base.have", lambda c: False)
    apk.reset_simulation()
    apk._installed.cache_clear()
    assert apk.pending_upgrades() == []
    assert ApkPlugin().detect() is False and OpensshApkPlugin().detect() is False
    rep = OpensshApkPlugin().report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    apk._installed.cache_clear()
