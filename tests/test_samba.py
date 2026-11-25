# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#133: the Samba plugin (``testparm -s`` output parsed as text)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import samba as sb
from kevward.util import Cmd

# `testparm -s` on a stock Ubuntu install.
STOCK = """\
# Global parameters
[global]
\tlog file = /var/log/samba/log.%m
\tmap to guest = Bad User
\tserver role = standalone server
\tusershare allow guests = Yes
\tidmap config * : backend = tdb


[printers]
\tbrowseable = No
\tcomment = All Printers
\tpath = /var/spool/samba
\tprintable = Yes
"""

RESTRICTED = """\
[global]
\tbind interfaces only = Yes
\tinterfaces = 127.0.0.0/8 eth0
\tserver role = standalone server

[share]
\tinterfaces = ignored here
\tpath = /srv/share
"""


def _sev(text: str) -> list[str]:
    return [t for _, t, _ in sb.classify(sb.parse_global(text))]


def test_parse_global_only():
    g = sb.parse_global(RESTRICTED)
    assert g["interfaces"] == "127.0.0.0/8 eth0" and g["bind interfaces only"] == "Yes"
    assert "path" not in g


def test_stock_listens_everywhere():
    assert _sev(STOCK) == ["Samba listens on every interface"]


def test_restricted():
    assert _sev(RESTRICTED) == []
    assert _sev("[global]\n\tinterfaces = eth0\n") == ["Samba listens on every interface"]
    assert _sev("[global]\n\tbind interfaces only = Yes\n") == [
        "Samba listens on every interface"]


def test_smb1():
    fs = sb.classify(sb.parse_global(RESTRICTED.replace(
        "\tserver role", "\tserver min protocol = NT1\n\tserver role")))
    assert [(s, t) for s, t, _ in fs] == [
        (Severity.LOW, "Samba allows SMB1 (server min protocol = NT1)")]
    assert _sev(RESTRICTED + "[global]\n\tmin protocol = LANMAN2\n")[0].endswith("LANMAN2)")
    assert _sev(RESTRICTED.replace("\tserver role", "\tserver min protocol = SMB2_02\n"
                                   "\tserver role")) == []


def test_testparm_failure_adds_nothing(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade", lambda: [])
    monkeypatch.setattr(sb, "run", lambda *a, **k: Cmd(1, "", "no smb.conf"))
    assert sb.SambaPlugin().check() == []
    monkeypatch.setattr(sb, "run", lambda *a, **k: Cmd(0, STOCK, ""))
    assert [f.severity for f in sb.SambaPlugin().check()] == [Severity.LOW]


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = sb.SambaPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["samba", "samba-common-bin"], "smbd.service", ["samba"])
