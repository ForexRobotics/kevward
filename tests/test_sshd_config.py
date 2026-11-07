# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

from kevward.model import Severity
from kevward.plugins.sshd import classify_sshd_config


def _titles(cfg):
    return {t: s for s, t, _ in classify_sshd_config(cfg)}


def test_hardened_config_is_clean():
    cfg = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "logingracetime": "30",
        "x11forwarding": "no",
    }
    assert classify_sshd_config(cfg) == []


def test_logingracetime_zero_is_medium():
    got = _titles({"logingracetime": "0", "maxstartups": "10:30:100"})
    title = "LoginGraceTime 0 (unauthenticated connections never time out)"
    assert got[title] is Severity.MEDIUM
    detail = next(d for _, t, d in classify_sshd_config(
        {"logingracetime": "0", "maxstartups": "10:30:100"}) if t == title)
    assert "10:30:100" in detail and "CVE-2024-6387" in detail


def test_logingracetime_nonzero_not_flagged():
    for v in ("120", "30", "1"):
        assert not any("LoginGraceTime" in t for _, t, _ in
                       classify_sshd_config({"logingracetime": v}))


def test_root_login_without_password_spelling_is_caught():
    # Ubuntu 22.04's `sshd -T` prints the legacy spelling; it was missed before.
    assert _titles({"permitrootlogin": "without-password"})[
        "PermitRootLogin without-password"] is Severity.LOW
    assert _titles({"permitrootlogin": "prohibit-password"})[
        "PermitRootLogin prohibit-password"] is Severity.LOW


def test_root_login_yes_is_high():
    assert _titles({"permitrootlogin": "yes"})["PermitRootLogin yes"] is Severity.HIGH


def test_existing_checks_kept():
    got = _titles({"passwordauthentication": "yes", "x11forwarding": "yes"})
    assert got["Password authentication enabled"] is Severity.MEDIUM
    assert got["X11Forwarding enabled"] is Severity.LOW
