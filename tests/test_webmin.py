# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#137: the Webmin plugin (/etc/webmin/miniserv.conf read as text)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import webmin as wm

# The start of a fresh miniserv.conf from the Webmin apt package.
FRESH = """\
port=10000
root=/usr/share/webmin
mimetypes=/usr/share/webmin/mime.types
addtype_cgi=internal/cgi
realm=Webmin Server
logfile=/var/webmin/miniserv.log
pidfile=/var/webmin/miniserv.pid
ssl=1
keyfile=/etc/webmin/miniserv.pem
"""


def _sev(text: str) -> list[Severity]:
    return [s for s, _, _ in wm.classify(wm.parse_miniserv(text))]


def test_parse_miniserv():
    conf = wm.parse_miniserv(FRESH + "# allow=1.2.3.4\nallow=10.0.0.0/8 192.168.1.5\n")
    assert conf["port"] == "10000" and conf["allow"] == "10.0.0.0/8 192.168.1.5"
    assert wm.parse_miniserv("") == {}


def test_open_panel():
    assert _sev(FRESH) == [Severity.LOW]
    assert "port 10000" in wm.classify(wm.parse_miniserv(FRESH))[0][1]
    assert _sev(FRESH + "allow=\n") == [Severity.LOW]          # empty allow
    assert _sev(FRESH + "#allow=10.0.0.0/8\n") == [Severity.LOW]


def test_restricted_panel():
    assert _sev(FRESH + "allow=10.0.0.0/8 LOCAL\n") == []
    assert _sev(FRESH + "bind=127.0.0.1\n") == []
    assert _sev(FRESH + "bind=0.0.0.0\n") == [Severity.LOW]


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = wm.WebminPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["webmin"], "webmin.service", ["webmin"])
