# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#38: dangerous file capabilities (``getcap -r`` parsed as text)."""

from __future__ import annotations

from kevward import audit as ad
from kevward.model import Severity
from kevward.util import Cmd

# `getcap -r /usr/bin /usr/sbin /tmp` on Ubuntu 24.04 plus planted backdoors.
GETCAP = """\
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/libexec/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/bin/python3.12 cap_setuid=ep
/tmp/.x/helper cap_dac_read_search=ep
/usr/local/bin/backup cap_dac_override,cap_chown+ep
/usr/sbin/tool =ep
/usr/bin/inh cap_setuid=i
"""


def test_parse_getcap_line():
    assert ad.parse_getcap_line("/usr/bin/ping cap_net_raw=ep") == (
        "/usr/bin/ping", {"cap_net_raw"}, False)
    assert ad.parse_getcap_line("/usr/bin/ping = cap_net_raw+ep") == (
        "/usr/bin/ping", {"cap_net_raw"}, False)                          # old libcap
    assert ad.parse_getcap_line("/bin/x cap_setuid,cap_net_raw=ep cap_chown=i") == (
        "/bin/x", {"cap_setuid", "cap_net_raw"}, False)
    assert ad.parse_getcap_line("/usr/sbin/tool =ep") == ("/usr/sbin/tool", set(), True)
    assert ad.parse_getcap_line("/usr/bin/inh cap_setuid=i") == ("/usr/bin/inh", set(), False)
    assert ad.parse_getcap_line("/path with space/bin cap_chown=ep")[0] == "/path with space/bin"
    assert ad.parse_getcap_line("getcap: /root: Permission denied") is None
    assert ad.parse_getcap_line("") is None


def test_classify_caps():
    assert ad.classify_caps("/usr/bin/ping", {"cap_net_raw"}) is None
    assert ad.classify_caps("/usr/bin/python3.12", {"cap_setuid"})[0] is Severity.HIGH
    assert ad.classify_caps("/usr/bin/perl", {"cap_dac_read_search"})[0] is Severity.HIGH
    assert ad.classify_caps("/tmp/.x/helper", {"cap_chown"}, packaged=False)[1].endswith(
        "temp or hidden path")
    assert ad.classify_caps("/home/u/.local/bin/x", {"cap_sys_admin"})[0] is Severity.HIGH
    assert ad.classify_caps("/usr/sbin/tool", set(), every=True) == (
        Severity.HIGH, "every capability granted")
    assert ad.classify_caps("/usr/local/bin/backup", {"cap_dac_override"},
                            packaged=False)[0] is Severity.MEDIUM
    sev, why = ad.classify_caps("/usr/bin/newuidmap", {"cap_setuid"}, packaged=True)
    assert sev is Severity.LOW and "cap_setuid" in why


def test_check_caps(monkeypatch):
    monkeypatch.setattr(ad, "have", lambda c: True)
    monkeypatch.setattr(ad, "_home_dirs", lambda: [])
    monkeypatch.setattr(ad.os.path, "isdir", lambda d: True)
    calls = []

    def fake_run(argv, timeout=0, **k):
        calls.append(argv)
        if argv[0] == "getcap":
            return Cmd(1, GETCAP, "getcap: /root: Permission denied")   # partial, still read
        return Cmd(0 if argv[-1].startswith("/usr/bin/") else 1, "", "")

    monkeypatch.setattr(ad, "run", fake_run)
    fs = {f.title: f.severity for f in ad._check_caps()}
    assert fs == {
        "file capability: cap_setuid on a shell or interpreter: /usr/bin/python3.12":
            Severity.HIGH,
        "file capability: cap_dac_read_search on a file in a temp or hidden path: "
        "/tmp/.x/helper": Severity.HIGH,
        "file capability: cap_chown, cap_dac_override on a file no package owns: "
        "/usr/local/bin/backup": Severity.MEDIUM,
        "file capability: every capability granted: /usr/sbin/tool": Severity.HIGH,
    }
    assert calls[0][:2] == ["getcap", "-r"]
    # only flagged files are looked up in dpkg, never ping & co.
    assert all("ping" not in c[-1] for c in calls[1:])


def test_no_getcap(monkeypatch):
    monkeypatch.setattr(ad, "have", lambda c: False)
    assert ad._check_caps() == []
