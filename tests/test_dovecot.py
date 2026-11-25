# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#130: the Dovecot plugin (``doveconf -n`` parsed as text)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import dovecot as dv
from kevward.util import Cmd

# `doveconf -n` on a stock Ubuntu install (trimmed).
STOCK = """\
# 2.3.21 (47349e2482): /etc/dovecot/dovecot.conf
# OS: Linux 6.8.0-45-generic x86_64 Ubuntu 24.04.1 LTS
mail_location = mbox:~/mail:INBOX=/var/mail/%u
mail_privileged_group = mail
namespace inbox {
  inbox = yes
  location =
  mailbox Drafts {
    special_use = \\Drafts
  }
  prefix =
}
passdb {
  driver = pam
}
protocols = " imap"
ssl_cert = </etc/dovecot/private/dovecot.pem
ssl_client_ca_dir = /etc/ssl/certs
ssl_dh = # hidden, use -P to show it
ssl_key = # hidden, use -P to show it
userdb {
  driver = passwd
}
"""


def test_parse_top_level_only():
    c = dv.parse_doveconf(STOCK + "service imap {\n  ssl = no\n}\n")
    assert c["mail_privileged_group"] == "mail" and "driver" not in c
    assert "ssl" not in c and "inbox" not in c


def test_stock_is_fine():
    assert dv.cleartext_passwords(dv.parse_doveconf(STOCK)) is False


def test_cleartext():
    assert dv.cleartext_passwords(dv.parse_doveconf(
        STOCK + "disable_plaintext_auth = no\nssl = no\n"))
    assert dv.cleartext_passwords(dv.parse_doveconf(
        STOCK + "auth_allow_cleartext = yes\nssl = no\n"))       # 2.4 name


def test_one_alone_is_not_enough():
    assert not dv.cleartext_passwords(dv.parse_doveconf(STOCK + "ssl = no\n"))
    assert not dv.cleartext_passwords(dv.parse_doveconf(
        STOCK + "disable_plaintext_auth = no\n"))
    assert not dv.cleartext_passwords(dv.parse_doveconf(
        STOCK + "disable_plaintext_auth = no\nssl = required\n"))


def test_check(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade", lambda: [])
    monkeypatch.setattr(dv, "run", lambda *a, **k: Cmd(1, "", "doveconf: fatal"))
    assert dv.DovecotPlugin().check() == []
    monkeypatch.setattr(dv, "run", lambda *a, **k: Cmd(
        0, STOCK + "disable_plaintext_auth = no\nssl = no\n", ""))
    assert [f.severity for f in dv.DovecotPlugin().check()] == [Severity.MEDIUM]


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = dv.DovecotPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["dovecot-core", "dovecot-imapd", "dovecot-pop3d"], "dovecot.service", ["dovecot"])
