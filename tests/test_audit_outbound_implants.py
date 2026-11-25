# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#31: outbound connections from non-shell implants and tunnels.
Fake `ss -tnap` output and process info; no host/root."""

from __future__ import annotations

from kevward import audit as ad
from kevward.model import Severity
from kevward.util import Cmd


def test_classify_outbound_proc():
    # tmpfs-resident beacon (SysGoRAT-style, over wss:// on 443)
    assert ad.classify_outbound_proc("/dev/shm/.x/sysupd", "sysupd") == \
        "runs from a temp/world-writable path"
    assert ad.classify_outbound_proc("/tmp/beacon (deleted)", "beacon").startswith(
        "runs from a deleted temp")
    # GSocket's usual install path is hidden inside ~/.config
    assert ad.classify_outbound_proc("/home/u/.config/dbus/gs-dbus", "gs-dbus") == \
        "runs from a hidden directory"
    assert ad.classify_outbound_proc("/usr/local/bin/gs-netcat", "gs-netcat") == \
        "tunnel/relay tool (gs-netcat)"
    assert ad.classify_outbound_proc("/opt/tools/revsocks", "revsocks") == \
        "tunnel/relay tool (revsocks)"
    assert ad.classify_outbound_proc("/usr/sbin/agent", "[kcached]") == \
        "wears a kernel-thread name ([kcached])"
    assert ad.classify_outbound_proc("/usr/sbin/agent", "agent", histfile_null=True) == \
        "HISTFILE=/dev/null in its environment"
    assert "deleted" in ad.classify_outbound_proc("/usr/sbin/old (deleted)", "old")
    # ordinary clients are NOT flagged
    assert ad.classify_outbound_proc("/usr/bin/curl", "curl") is None
    assert ad.classify_outbound_proc("/usr/lib/apt/methods/http", "http") is None
    assert ad.classify_outbound_proc("", "") is None          # unreadable (not root)


def test_histfile_disabled():
    assert ad.histfile_disabled(b"PATH=/usr/bin\x00HISTFILE=/dev/null\x00HOME=/root\x00")
    assert not ad.histfile_disabled(b"HISTFILE=/root/.bash_history\x00")
    assert not ad.histfile_disabled(b"")


HDR = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
SS = HDR + "\n".join([
    # normal curl to an Ubuntu mirror: must NOT flag
    'ESTAB 0 0 10.0.0.5:51000 91.189.91.81:443 users:(("curl",pid=100,fd=5))',
    # tmpfs beacon on 443 (a well-known port: still flagged)
    'ESTAB 0 0 10.0.0.5:51002 45.142.212.9:443 users:(("sysupd",pid=200,fd=7))',
    # gs-netcat to the GSocket relay network
    'ESTAB 0 0 10.0.0.5:51004 46.101.10.20:7350 users:(("gs-netcat",pid=300,fd=3))',
    # allowlisted tor: an allow rule must not hide an implant trait
    'ESTAB 0 0 10.0.0.5:51006 157.180.60.60:9001 users:(("tor",pid=400,fd=12))',
])

INFO = {
    100: ("/usr/bin/curl", "curl", False, "1000"),
    200: ("/dev/shm/.x/sysupd (deleted)", "sysupd", False, "0"),
    300: ("/usr/local/bin/gs-netcat", "gs-netcat", True, "1000"),
    400: ("/usr/bin/tor", "tor", False, "112"),
}


def test_check_connections_flags_implants(monkeypatch):
    monkeypatch.setattr(ad, "run", lambda *a, **k: Cmd(0, SS, ""))
    rules, _ = ad.parse_outbound_allow(["tor:9001"])
    hits: dict[str, int] = {}
    fs = ad.check_connections(allow=rules, hits=hits,
                              proc_info=lambda pid: INFO.get(pid, ("", "", False, "")))
    high = [f.title for f in fs if f.severity is Severity.HIGH]
    assert high == [
        "possible implant/tunnel: sysupd (pid 200, uid 0) -> 45.142.212.9:443: "
        "runs from a deleted temp/world-writable path",
        "possible implant/tunnel: gs-netcat (pid 300, uid 1000) -> 46.101.10.20:7350: "
        "tunnel/relay tool (gs-netcat)",
    ]
    assert not any("curl" in f.title for f in fs)
    assert hits == {"tor:9001": 1}
