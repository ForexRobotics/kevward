# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#252: multipass / LXD plumbing on a Linux host is recognised, counted, and
nothing else from the same names is."""

from __future__ import annotations

from kevward import audit as ad
from kevward.util import Cmd

HDR = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
SS = HDR + "\n".join([
    'LISTEN 0 32 10.47.163.1:53 0.0.0.0:* users:(("dnsmasq",pid=100,fd=6))',
    'ESTAB 0 0 10.47.163.1:51122 10.47.163.20:22 users:(("multipassd",pid=200,fd=31))',
    'LISTEN 0 32 10.120.5.1:53 0.0.0.0:* users:(("dnsmasq",pid=300,fd=6))',
    # same names, not multipass's: still go through the normal checks
    'LISTEN 0 32 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=400,fd=6))',
    'ESTAB 0 0 160.16.1.2:51124 151.101.1.1:22 users:(("multipassd",pid=200,fd=32))',
    'LISTEN 0 5 10.47.163.1:4444 0.0.0.0:* users:(("bash",pid=500,fd=3))',
])
EXE = {100: "/snap/multipass/14002/usr/sbin/dnsmasq",
       200: "/snap/multipass/14002/bin/multipassd",
       300: "/snap/lxd/31000/bin/dnsmasq",
       400: "/usr/sbin/dnsmasq",
       500: "/usr/bin/bash"}


def test_recognised_and_counted(monkeypatch):
    monkeypatch.setattr(ad, "run", lambda *a, **k: Cmd(0, SS, ""))
    rec: dict[str, int] = {}
    fs = ad.check_connections(recognised=rec, exe_of=EXE.get)
    assert rec == {"multipass": 2, "lxd": 1}
    titles = [f.title for f in fs]
    # a shell listening on the bridge is still a bind backdoor
    assert any("shell listening on 10.47.163.1:4444" in t for t in titles)


def test_vm_plumbing_rules():
    vp = ad.vm_plumbing
    assert vp("dnsmasq", EXE[100], "LISTEN", "10.47.163.1:53", "0.0.0.0:*") == "multipass"
    assert vp("dnsmasq", EXE[400], "LISTEN", "10.47.163.1:53", "0.0.0.0:*") is None  # not snap
    assert vp("dnsmasq", EXE[100], "LISTEN", "0.0.0.0:53", "0.0.0.0:*") is None      # wildcard
    assert vp("dnsmasq", EXE[100], "LISTEN", "160.16.1.2:53", "0.0.0.0:*") is None   # public
    assert vp("multipassd", EXE[200], "ESTAB", "10.0.0.1:5", "10.47.163.20:22") == "multipass"
    assert vp("multipassd", EXE[200], "ESTAB", "10.0.0.1:5", "10.47.163.20:8080") is None
    assert vp("multipassd", EXE[200], "ESTAB", "1.2.3.4:5", "151.101.1.1:22") is None
    assert vp("multipassd", "/tmp/multipassd", "ESTAB", "x:1", "10.47.163.20:22") is None
    assert vp("lxd", "/snap/multipass/1/lxd", "LISTEN", "10.1.1.1:8443", "*:*") is None
