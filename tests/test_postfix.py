# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#129: Postfix plugin and its postconf -n classifier."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugin import discover
from kevward.plugins import postfix
from kevward.plugins.postfix import (
    classify_postfix_config,
    parse_postconf,
    wide_networks,
)

SEND_ONLY = """\
inet_interfaces = loopback-only
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
smtp_tls_security_level = may
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
"""


def _titles(text):
    return {t: s for s, t, _ in classify_postfix_config(parse_postconf(text))}


def test_discovered():
    assert discover()["postfix"] is postfix.PostfixPlugin


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = postfix.PostfixPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["postfix"], "postfix.service", ["postfix"])


def test_parse_main_cf_comments_and_continuations():
    cfg = parse_postconf(
        "# comment\n"
        "smtpd_relay_restrictions = permit_mynetworks,\n"
        "    reject_unauth_destination\n"
        "\n"
        "myhostname = mail.example.com\n"
    )
    assert cfg == {
        "smtpd_relay_restrictions": "permit_mynetworks, reject_unauth_destination",
        "myhostname": "mail.example.com",
    }


def test_send_only_host_is_clean():
    assert _titles(SEND_ONLY) == {}


def test_defaults_are_not_an_open_relay():
    got = _titles("smtp_tls_security_level = may\n")
    assert not any("open relay" in t for t in got)
    assert got["SMTP listening on the network"] is Severity.LOW


def test_relay_without_unauth_destination_is_high():
    got = _titles(SEND_ONLY.replace("defer_unauth_destination", "permit"))
    assert got["Possible open relay (no reject_unauth_destination)"] is Severity.HIGH


def test_legacy_recipient_restrictions_count():
    text = SEND_ONLY.replace("defer_unauth_destination", "") + (
        "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination\n")
    assert _titles(text) == {}


def test_wide_mynetworks_is_high():
    got = _titles(SEND_ONLY.replace("127.0.0.0/8", "0.0.0.0/0"))
    assert got["Possible open relay (very wide mynetworks)"] is Severity.HIGH


def test_wide_networks():
    assert wide_networks("0.0.0.0/0 [::]/0 8.0.0.0/8 10.0.0.0/8 "
                         "192.168.0.0/16 hash:/etc/postfix/network_table") == [
        "0.0.0.0/0", "[::]/0", "8.0.0.0/8"]


def test_inet_interfaces_all_is_low():
    got = _titles(SEND_ONLY.replace("loopback-only", "all"))
    assert got == {"SMTP listening on the network": Severity.LOW}


def test_no_outbound_tls_is_low():
    got = _titles(SEND_ONLY.replace("= may", "= none"))
    assert got == {"No TLS on outbound SMTP": Severity.LOW}
    assert _titles(SEND_ONLY.replace("smtp_tls_security_level = may",
                                     "smtp_use_tls = yes")) == {}
