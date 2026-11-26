# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#283 NEW source, #285 whether the caller's address is exempt."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import gate_sources as gs
from kevward import ssh_gate as g
from kevward.config import Config, SshGateConfig
from kevward.model import Severity

NOW = datetime(2026, 11, 26, 0, 30, tzinfo=timezone.utc)
CONSOLE, HOTEL = "124.44.207.82", "221.188.80.53"


def rec(t, client, kind="self.update", key=None):
    r = {"time": t, "client": client, "kind": kind}
    if key:
        r["key"] = key
    return r


HISTORY = [rec("2026-11-20T01:00:00+00:00", CONSOLE),
           rec("2026-11-24T01:00:00+00:00", CONSOLE, "apply.start"),
           rec("2026-11-25T14:21:00+00:00", HOTEL, key="console-operate"),
           rec("2026-11-25T14:30:00+00:00", HOTEL, "report.refresh", key="console-operate")]


def test_new_source_medium():
    fs = gs.new_source_findings(HISTORY, NOW, lambda a: False)
    assert len(fs) == 1 and fs[0].severity == Severity.MEDIUM
    assert fs[0].title == ("NEW source: self.update, report.refresh via ssh-gate from "
                           f"{HOTEL} (key console-operate)")
    assert "2 operation(s)" in fs[0].detail


def test_old_and_known_sources_are_quiet():
    assert gs.new_source_findings(HISTORY, NOW, lambda a: a == HOTEL) == []
    later = NOW.replace(day=28)                          # > 2 days after first use
    assert gs.new_source_findings(HISTORY, later, lambda a: False) == []
    # a source used long ago is not new even when used again now
    again = HISTORY + [rec("2026-11-26T00:00:00+00:00", CONSOLE)]
    assert [f.title for f in gs.new_source_findings(again, NOW, lambda a: False)
            if CONSOLE in f.title] == []


def test_setup_and_local_records_ignored():
    recs = [rec("2026-11-26T00:00:00+00:00", "", "apply.finish"),
            {"time": "2026-11-26T00:00:00+00:00", "kind": "setup", "client": "local"}]
    assert gs.new_source_findings(recs, NOW, lambda a: False) == []


def test_matches():
    assert gs.matches(HOTEL, ["221.188.80.0/24"])
    assert gs.matches("2001:db8::5", ["2001:db8::/32"])
    assert not gs.matches(HOTEL, ["124.44.207.82", "example.org", "%(x)s", ""])
    assert not gs.matches("not-an-ip", ["0.0.0.0/0"])


def test_fail2ban_ignoreip(tmp_path):
    assert gs.fail2ban_ignoreip(tmp_path / "none") is None
    (tmp_path / "jail.d").mkdir()
    (tmp_path / "jail.conf").write_text("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n")
    (tmp_path / "jail.d" / "kevward-console.local").write_text(
        f"[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 {CONSOLE}\n")
    (tmp_path / "jail.d" / "z.local").write_text(
        "[sshd]\nenabled = true\nignoreip = %(known/ignoreip)s 198.51.100.7\n")
    toks = gs.fail2ban_ignoreip(tmp_path)
    assert CONSOLE in toks and "198.51.100.7" in toks and not any("%(" in t for t in toks)


def test_persisted_allow():
    text = """table inet kevward {
\tset allow4 {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 10.0.0.0/8, 124.44.207.82,
\t\t\t     192.168.0.0/16 }
\t}
\tset blocklist4 {
\t\ttype ipv4_addr
\t\telements = { 203.0.113.9 }
\t}
}
"""
    got = gs._persisted_allow(text)
    assert "124.44.207.82" in got and "203.0.113.9" not in got


def test_firewall_allow(tmp_path):
    cfg = Config()
    assert gs.firewall_allow(cfg, in_use=False) is None
    toks = gs.firewall_allow(cfg, in_use=True,
                             persisted="set allow4 {\n elements = { 124.44.207.82 }\n}")
    assert gs.matches(CONSOLE, toks) and gs.matches("10.1.2.3", toks)
    assert not gs.matches(HOTEL, toks)


def test_address_status():
    cfg = Config()
    s = gs.address_status(HOTEL, cfg, f2b=["127.0.0.1/8", CONSOLE], fw_allow=None,
                          seen={CONSOLE})
    assert s == {"address": HOTEL, "fail2ban_ignored": False, "firewall_allowed": None,
                 "configured": False, "seen_before": False, "known_source": False}
    cfg.ssh_gate = SshGateConfig(known_sources=["221.188.80.0/24"])
    assert gs.address_status(HOTEL, cfg, f2b=None, fw_allow=None)["known_source"]
    s = gs.address_status(CONSOLE, Config(), f2b=[CONSOLE], fw_allow=[CONSOLE])
    assert s["fail2ban_ignored"] and s["firewall_allowed"] and s["known_source"]


def test_known_sources_validated():
    with pytest.raises(ValueError):
        SshGateConfig(known_sources=["hotel.example"])
    with pytest.raises(ValueError):
        SshGateConfig(known_sources="1.2.3.4")
    SshGateConfig(known_sources=["1.2.3.4", "2001:db8::/32"])


def test_host_new_source_findings(tmp_path):
    p = tmp_path / "changes.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in HISTORY) + "garbage\n")
    fs = gs.host_new_source_findings(Config(), p, NOW, f2b=[CONSOLE], fw_allow=None)
    assert len(fs) == 1 and HOTEL in fs[0].title
    fs = gs.host_new_source_findings(Config(), p, NOW, f2b=[CONSOLE, HOTEL], fw_allow=None)
    assert fs == []


def test_capabilities_returns_client(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[ssh_gate]\nenabled = true\ntruthgate_path = "{tmp_path}/no"\n')
    resp = g.handle(b'{"op":"gate.capabilities"}', "read", path=cfg,
                    changes_file=tmp_path / "c.jsonl", client=HOTEL,
                    op_opts={"client_status": lambda a: {"address": a, "known_source": False}})
    assert resp["data"]["client"] == {"address": HOTEL, "known_source": False}
    resp = g.handle(b'{"op":"gate.capabilities"}', "read", path=cfg,
                    changes_file=tmp_path / "c.jsonl", client=HOTEL)
    c = resp["data"]["client"]
    assert c["address"] == HOTEL and set(c) >= {"fail2ban_ignored", "firewall_allowed",
                                                "known_source"}


def test_known_sources_not_writable_through_gate():
    keys = {k["key"]: k for k in g.schema()["keys"]}
    assert not keys["ssh_gate.known_sources"].get("writable")
