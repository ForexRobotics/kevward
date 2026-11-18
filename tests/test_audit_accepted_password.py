# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#87 part 2: a password login the host's own settings rule out is HIGH."""

from __future__ import annotations

from kevward import audit as ad

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
    assert got == [("ktakahashi", "185.220.101.7", "password", 2, LOG[2])]


def test_password_auth_disabled_flags_any_password_login():
    got = ad.accepted_password_logins(LOG, set(), True)
    assert {(u, ip, m) for u, ip, m, _n, _l in got} == {
        ("ktakahashi", "185.220.101.7", "password"),
        ("deploy", "91.198.174.9", "password"),
    }  # keyboard-interactive (PAM/OTP) for an unlocked user is not flagged


def test_nothing_when_password_auth_allowed_and_unlocked():
    assert ad.accepted_password_logins(LOG, {"svc"}, False) == []


def test_keyboard_interactive_for_locked_account_is_flagged():
    got = ad.accepted_password_logins(LOG, {"deploy"}, False)
    assert ("deploy", "91.198.174.9", "keyboard-interactive/pam") in {
        (u, ip, m) for u, ip, m, _n, _l in got}


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
