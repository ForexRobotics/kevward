# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#40: rootkit indicators — discrepancies between two views of the same
kernel state. Pure classifiers on fixture text; no root/host."""

from __future__ import annotations

from kevward import audit as ad
from kevward.model import Severity
from kevward.util import Cmd

PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20011
   1: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 18340
   2: 0501000A:B7C2 5B1A4F33:01BB 01 00000000:00000000 02:00000A2C 00000000  1000        0 99887
"""
PROC_TCP6 = """\
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A
"""

SS = """\
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3)) ino:20011 sk:1 <->
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=600,fd=14)) ino:18340
LISTEN 0 64 0.0.0.0:41753 0.0.0.0:* ino:0 sk:3 <->
LISTEN 0 5 0.0.0.0:31337 0.0.0.0:* users:(("kworkerd",pid=4444,fd=3)) ino:66601 sk:4 <->
LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* ino:70001 sk:5 <->
"""

MODULES = """\
tls 155648 0 - Live 0x0000000000000000
nvidia 56713216 120 nvidia_modeset, Live 0x0000000000000000 (POE)
vboxdrv 696320 2 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)
diamorphine 16384 0 - Live 0x0000000000000000 (OE)
"""


def test_hidden_pids():
    assert ad.hidden_pids({1, 2, 10}, {1337, 4000}, {1, 2, 10, 4000}) == [1337]
    assert ad.hidden_pids({1, 2}, set(), {1, 2}) == []


def test_parse_proc_net_listen_ports():
    assert ad.parse_proc_net_listen_ports(PROC_TCP) == {22, 53}      # ESTAB row ignored
    assert ad.parse_proc_net_listen_ports(PROC_TCP6) == {22}
    assert ad.parse_proc_net_listen_ports("") == set()


def test_parse_ss_listeners():
    rows = ad.parse_ss_listeners(SS)
    assert [(p, o, i) for p, o, i, _ in rows] == [
        (22, True, 20011), (53, True, 18340), (41753, False, 0),
        (31337, True, 66601), (8080, False, 70001)]


def test_classify_listeners():
    proc = ad.parse_proc_net_listen_ports(PROC_TCP) | {41753, 8080}
    fs = ad.classify_listeners(ad.parse_ss_listeners(SS), proc)
    assert [(s, t) for s, t, _ in fs] == [
        (Severity.HIGH, "possible hidden port: listener on 31337 missing from /proc/net/tcp"),
        (Severity.MEDIUM, "listener on 8080 has no visible owning process"),
    ]
    # the kernel listener (lockd, ino 0) is never flagged; no /proc view -> no HIGH
    assert all(t != "possible hidden port" for _, t, _ in
               ad.classify_listeners(ad.parse_ss_listeners(SS), set()))


def test_classify_modules():
    mods = ad.parse_proc_modules(MODULES)
    assert mods == {"tls": "", "nvidia": "POE", "vboxdrv": "OE", "diamorphine": "OE"}
    fs = ad.classify_modules(mods, {"tls", "nvidia", "vboxdrv", "diamorphine", "reptile"})
    assert [(s, t) for s, t, _ in fs] == [
        (Severity.HIGH, "possible hidden kernel module: reptile"),
        (Severity.LOW, "kernel module diamorphine is out-of-tree, unsigned"),
    ]
    # no /proc/modules (container) -> no "hidden" claims
    assert ad.classify_modules({}, {"tls"}) == []


def test_not_root_is_silent(monkeypatch):
    monkeypatch.setattr(ad, "is_root", lambda: False)
    assert ad._check_rootkit() == []


def test_hidden_ports_collector(monkeypatch):
    monkeypatch.setattr(ad, "run", lambda *a, **k: Cmd(0, SS, ""))
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/proc/net/tcp":
            from io import StringIO
            return StringIO(PROC_TCP + "   9: 00000000:A319 00000000:0000 0A\n"
                                       "   9: 00000000:1F90 00000000:0000 0A\n")
        if path == "/proc/net/tcp6":
            raise OSError
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    titles = [f.title for f in ad._check_hidden_ports()]
    assert titles == ["possible hidden port: listener on 31337 missing from /proc/net/tcp",
                      "listener on 8080 has no visible owning process"]
