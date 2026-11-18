# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#87 part 2: a password login the host's own settings rule out is HIGH."""

from __future__ import annotations

from kevward import audit as ad
from kevward.audit import password_off_since

SHADOW = (
    "root:*:20000:0:99999:7:::\n"
    "ktakahashi:!$y$j9T$abc$def:20000:0:99999:7:::\n"
    "deploy:$y$j9T$xyz$uvw:20000:0:99999:7:::\n"
    "svc:!!:20000::::::\n"
)
LOG = [
    "2026-11-17T03:12:44.123456+09:00 www2 sshd[4242]: Accepted publickey for "
    "ktakahashi from 106.73.233.64 port 51022 ssh2: ED25519 SHA256:abc",
    "2026-11-17T03:13:01.000000+09:00 www2 sshd[4243]: Accepted password for "
    "ktakahashi from 185.220.101.7 port 40012 ssh2",
    "2026-11-17T03:14:01.000000+09:00 www2 sshd[4244]: Accepted password for "
    "ktakahashi from 185.220.101.7 port 40014 ssh2",
    "Nov 17 03:15:00 hokaku sshd[99]: Accepted password for deploy from 91.198.174.9 "
    "port 2222 ssh2",
    "Nov 17 03:16:00 hokaku sshd[100]: Accepted keyboard-interactive/pam for deploy "
    "from 91.198.174.9 port 2223 ssh2",
    "Nov 17 03:17:00 hokaku sshd[101]: Failed password for root from 1.2.3.4 port 1 ssh2",
]


def test_locked_accounts_never_keep_hashes():
    locked = ad.locked_accounts(SHADOW)
    assert locked == {"root", "ktakahashi", "svc"}
    assert all("$" not in n for n in locked)


def test_locked_account_password_login_is_flagged():
    got = ad.accepted_password_logins(LOG, ad.locked_accounts(SHADOW), None)
    assert got == [("ktakahashi", "185.220.101.7", "password", 2, LOG[2], False)]


def test_password_auth_disabled_flags_any_password_login():
    got = ad.accepted_password_logins(LOG, set(), True)
    assert {(u, ip, m) for u, ip, m, _n, _l, _b in got} == {
        ("ktakahashi", "185.220.101.7", "password"),
        ("deploy", "91.198.174.9", "password"),
    }  # keyboard-interactive (PAM/OTP) for an unlocked user is not flagged


def test_nothing_when_password_auth_allowed_and_unlocked():
    assert ad.accepted_password_logins(LOG, {"svc"}, False) == []


def test_keyboard_interactive_for_locked_account_is_flagged():
    got = ad.accepted_password_logins(LOG, {"deploy"}, False)
    assert ("deploy", "91.198.174.9", "keyboard-interactive/pam") in {
        (u, ip, m) for u, ip, m, _n, _l, _b in got}


def test_check_reads_logs_and_settings(monkeypatch, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(LOG) + "\n")
    import kevward.integrations.conditions as cond
    monkeypatch.setattr(cond, "_read_sshd_t", lambda: {"passwordauthentication": "no"})
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/etc/shadow":
            raise PermissionError(path)  # non-root: rely on sshd -T
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    fs = ad._check_accepted_password(str(log) + "*")
    titles = sorted(f.title for f in fs)
    assert len(fs) == 2 and all(f.severity.value == "high" for f in fs)
    assert "but sshd has PasswordAuthentication no (2x)" in titles[1]
    assert "possible authentication bypass" in fs[0].detail


# --- www2, 2026-11-18: password logins during initial setup on 2026-10-25,
# minutes before `PasswordAuthentication no` was written to sshd_config.
from datetime import datetime, timedelta, timezone  # noqa: E402

JST = timezone(timedelta(hours=9))
SET_AT = datetime(2026, 10, 25, 5, 7, 53, tzinfo=JST).timestamp()
WWW2 = [
    "2026-10-25T04:51:00.209316+09:00 tk2-248-33654 sshd[1819]: Accepted password for "
    "ubuntu from 124.44.207.82 port 59244 ssh2",
    "2026-10-25T04:52:51.720800+09:00 tk2-248-33654 sshd[1921]: Accepted password for "
    "ktakahashi from 124.44.207.82 port 53520 ssh2",
    "2026-11-17T03:00:00.000000+09:00 tk2-248-33654 sshd[9999]: Accepted password for "
    "ktakahashi from 185.220.101.7 port 40000 ssh2",
]
NOW = datetime(2026, 11, 18, 9, 0, tzinfo=JST)


def test_password_off_since_picks_earliest_file_that_sets_it():
    files = [("/etc/ssh/sshd_config", SET_AT, "#PasswordAuthentication yes\n"
              "PasswordAuthentication no\n"),
             ("/etc/ssh/sshd_config.d/10-hardening.conf", SET_AT + 5 * 86400,
              "PermitRootLogin no\nPasswordAuthentication no\n"),
             ("/etc/ssh/sshd_config.d/50-cloud-init.conf", SET_AT - 86400,
              "# PasswordAuthentication no\nPasswordAuthentication yes\n")]
    assert password_off_since(files) == (SET_AT, "/etc/ssh/sshd_config")
    assert password_off_since([("/x", 1.0, "PasswordAuthentication yes\n")]) is None


def test_logins_before_the_setting_are_not_a_bypass():
    got = ad.accepted_password_logins(WWW2, set(), True, off_since=SET_AT, now=NOW)
    before = {(u, b) for u, _ip, _m, _n, _l, b in got}
    assert before == {("ubuntu", True), ("ktakahashi", True), ("ktakahashi", False)}


def test_locked_account_is_never_excused_by_the_cutoff():
    got = ad.accepted_password_logins(WWW2[:1], {"ubuntu"}, True, off_since=SET_AT, now=NOW)
    assert got[0][5] is False


def test_check_splits_info_and_high(monkeypatch, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(WWW2) + "\n")
    import kevward.integrations.conditions as cond
    monkeypatch.setattr(cond, "_read_sshd_t", lambda: {"passwordauthentication": "no"})
    monkeypatch.setattr(ad, "_sshd_config_files", lambda: [
        ("/etc/ssh/sshd_config", SET_AT, "PasswordAuthentication no\n")])
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/etc/shadow":
            raise PermissionError(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    fs = ad._check_accepted_password(str(log) + "*")
    sev = sorted((f.severity.value, f.title.split(" from ")[0]) for f in fs)
    assert sev == [("high", "ssh password login accepted for ktakahashi"),
                   ("info", "ssh password login for ktakahashi"),
                   ("info", "ssh password login for ubuntu")]
    info = next(f for f in fs if "ubuntu" in f.title)
    assert "before password logins were turned off" in info.title
    assert "/etc/ssh/sshd_config" in info.detail
