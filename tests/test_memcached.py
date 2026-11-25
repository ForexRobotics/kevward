# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#136: the Memcached plugin (/etc/memcached.conf read as text)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import memcached as mc

# The option file Ubuntu/Debian ship.
UBUNTU_DEFAULT = """\
# memcached default config file
-d
logfile /var/log/memcached.log
-m 64
-p 11211
-u memcache
# Specify which IP address to listen on. The default is to listen on all IP addresses
# This parameter is one of the only security measures that memcached has, so make sure
# it's listening on a firewalled interface.
-l 127.0.0.1
-P /var/run/memcached/memcached.pid
"""

NEW = (1, 6, 14)
OLD = (1, 4, 25)


def _sev(text: str, version=NEW) -> list[Severity]:
    return [s for s, _, _ in mc.classify(mc.parse_conf(text), version)]


def test_parse_conf():
    c = mc.parse_conf(UBUNTU_DEFAULT)
    assert c.listen == ["127.0.0.1"] and c.udp_port is None and c.socket is None
    c = mc.parse_conf("-l 127.0.0.1,::1\n-l 10.0.0.5\n-U 0  # off\n")
    assert c.listen == ["127.0.0.1", "::1", "10.0.0.5"] and c.udp_port == "0"
    c = mc.parse_conf("--listen=0.0.0.0\n--udp-port=11211\n-s /run/memcached.sock\n")
    assert c.listen == ["0.0.0.0"] and c.udp_port == "11211" and c.socket


def test_default_is_local():
    assert _sev(UBUNTU_DEFAULT) == []
    assert _sev(UBUNTU_DEFAULT, OLD) == []           # loopback: UDP is local too
    assert _sev("-l 127.0.0.1,::1,localhost\n") == []
    assert _sev("-l [::1]:11211\n-l 127.0.0.1:11211\n") == []


def test_exposed():
    assert _sev("-p 11211\n") == [Severity.MEDIUM]   # no -l: all interfaces
    assert _sev("-l 0.0.0.0\n") == [Severity.MEDIUM]
    assert _sev("-l 127.0.0.1,192.168.1.5\n") == [Severity.MEDIUM]
    title = mc.classify(mc.parse_conf("-l 127.0.0.1\n-l 10.0.0.5:11211\n"))[0][1]
    assert "10.0.0.5:11211" in title and "127.0.0.1" not in title


def test_udp():
    assert _sev("-l 0.0.0.0\n-U 11211\n") == [Severity.MEDIUM, Severity.LOW]
    assert _sev("-l 0.0.0.0\n-U 0\n", OLD) == [Severity.MEDIUM]
    assert _sev("-l 0.0.0.0\n", OLD) == [Severity.MEDIUM, Severity.LOW]
    assert _sev("-l 0.0.0.0\n", None) == [Severity.MEDIUM]   # version unknown


def test_unix_socket_turns_network_off():
    assert _sev("-s /run/memcached/memcached.sock\n-U 11211\n") == []


def test_parse_version():
    assert mc.parse_version("memcached 1.6.14-1ubuntu0.1") == (1, 6, 14)
    assert mc.parse_version("memcached 1.4.25-2ubuntu1") == (1, 4, 25)
    assert mc.parse_version(None) is None


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = mc.MemcachedPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["memcached"], "memcached.service", ["memcached"])
