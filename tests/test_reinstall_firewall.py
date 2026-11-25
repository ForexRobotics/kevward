# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#243 firewall back after a reinstall, #244 warning when it is missing,
#245 previous-report comparison placement, #246 report sandbox."""

from __future__ import annotations

import json
from pathlib import Path

from kevward import engine, firewall
from kevward import schedule as sch
from kevward import setup as su
from kevward.engine import RunResult
from kevward.reporting.html import render
from kevward.util import Cmd

# --- #243 -----------------------------------------------------------------------

def test_marker(tmp_path):
    p = str(tmp_path / "lib" / "firewall.json")
    assert not firewall.in_use(p)
    firewall.mark_in_use(p, persist=True)
    assert firewall.in_use(p) and json.loads(Path(p).read_text())["persist"] is True


class Runner:
    def __init__(self, table=False, rc=0):
        self.calls, self.table, self.rc = [], table, rc

    def __call__(self, argv, timeout=0, **_k):
        self.calls.append(argv)
        if argv[:2] == ["nft", "list"]:
            return Cmd(0 if self.table else 1, "", "")
        return Cmd(self.rc, "added 85 IP(s)", "boom" if self.rc else "")


def _env(tmp_path, runner):
    return su.Env(etc=tmp_path / "etc", unit_dir=tmp_path / "units",
                  changes_file=tmp_path / "c.jsonl", runner=runner,
                  is_root=lambda: True, state_dir=tmp_path / "lib",
                  prefix=Path("/opt/kevward"))


def test_plain_setup_reports_missing_blocklist(tmp_path):
    r = Runner(table=False)
    env = _env(tmp_path, r)
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "firewall.json").write_text("{}")
    (tmp_path / "units").mkdir()
    (tmp_path / "units" / sch.SERVICE).write_text("[Service]\n")
    d = su.setup(refresh=True, env=env, dry_run=True)
    fw = [a for a in d["actions"] if a["kind"] == "firewall"]
    assert fw and fw[0]["action"] == "skipped" and "setup --restore" in fw[0]["hint"]
    assert not any(c[1:3] == ["firewall", "apply"] for c in r.calls)
    r.table = True
    d = su.setup(refresh=True, env=env, dry_run=True)
    assert [a["action"] for a in d["actions"] if a["kind"] == "firewall"] == ["unchanged"]


def test_restore_applies_firewall_with_console_allowed(tmp_path, monkeypatch):
    r = Runner(table=False)
    env = _env(tmp_path, r)
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps({"version": 1, "users": [], "timer": None,
                                "fail2ban_ignore": ["124.44.207.82/32"], "firewall": True}))
    monkeypatch.setattr(su, "setup", lambda **kw: {"dry_run": kw["dry_run"], "changed": False,
                                                   "actions": []})
    d = su.restore(path=snap, env=env, dry_run=True)
    assert d["actions"] == [{"kind": "firewall", "path": "nft inet kevward",
                             "action": "apply", "allow": ["124.44.207.82/32"]}]
    d = su.restore(path=snap, env=env)
    assert ["/opt/kevward/bin/kevward", "firewall", "apply", "--yes",
            "--allow", "124.44.207.82/32"] in r.calls
    assert d["changed"] is False or d["actions"][-1]["action"] == "apply"
    r.rc = 1
    import pytest

    from kevward.ssh_gate import GateError
    with pytest.raises(GateError) as e:
        su.restore(path=snap, env=env)
    assert "firewall apply failed" in e.value.message


# --- #244 -----------------------------------------------------------------------

def test_expected_but_missing_and_finding():
    assert not firewall.expected_but_missing({"table": True, "unit": "enabled"})
    assert not firewall.expected_but_missing({"table": None, "in_use": True})
    assert not firewall.expected_but_missing({"table": False, "unit": "not-found"})
    assert firewall.expected_but_missing({"table": False, "unit": "not-found", "in_use": True})
    assert firewall.expected_but_missing({"table": False, "unit": "enabled"})
    (f,) = engine.firewall_missing_findings({"table": False, "in_use": True})
    assert f.severity.value == "high" and "applied on this host before" in f.detail
    assert engine.firewall_missing_findings({"table": True}) == []


def test_html_warns_and_keeps_drops_line():
    r = RunResult(host="h", generated_at="2026-11-25T00:00:00+00:00", os="Linux")
    r.attackers = {"firewall": {}, "firewall_state": {"table": False, "unit": "not-found",
                                                      "in_use": True}}
    html = render(r)
    assert "firewall drops: <b>not loaded</b>" in html
    assert "kevward firewall not loaded" in html and "setup --restore" in html
    ja = render(r, lang="ja")
    assert "読み込まれていません" in ja
    r.attackers["firewall_state"] = {"table": False, "unit": "not-found", "in_use": False}
    assert "not loaded" not in render(r)


# --- #245 -----------------------------------------------------------------------

def test_previous_comparison_next_to_24h():
    r = RunResult(host="h", generated_at="t", os="Linux")
    r.attackers = {"logwatch": {"ssh_total_attempts": 500, "ssh_attempts_24h": 110,
                                "ssh_attempts_7d": 305, "ssh_sources_24h": 9,
                                "ssh_window_start": "2026-11-18T00:00:00+00:00",
                                "ssh_window_end": "2026-11-25T00:00:00+00:00"},
                   "previous": {"generated_at": "x", "ssh_failed_24h": 27}}
    html = render(r)
    i24, iprev, i7 = (html.index("last 24h"), html.index("(previous report: 27, +307%)"),
                      html.index("last 7d"))
    assert i24 < iprev < i7
    ja = render(r, lang="ja")
    assert ja.index("前回のレポート") < ja.index("直近 7 日")


# --- #246 -----------------------------------------------------------------------

def test_dropin_turns_off_protecthome_and_privatetmp():
    text = sch.render_service_dropin()
    assert "ProtectHome=no" in text and "PrivateTmp=no" in text


def test_status_warns_on_hidden_home_and_tmp():
    base = {"UnitFileState": "enabled", "ActiveState": "active",
            "RandomizedDelayUSec": "20min", "FixedRandomDelay": "yes"}
    w = sch.status_warnings({**base, "ProtectHome": "yes", "PrivateTmp": "yes"}, True)
    assert any("ProtectHome=yes" in x for x in w) and any("PrivateTmp=yes" in x for x in w)
    assert sch.status_warnings({**base, "ProtectHome": "no", "PrivateTmp": "no"}, True) == []


def test_example_unit_matches_template():
    repo = Path(__file__).resolve().parent.parent
    example = (repo / "systemd" / "kevward-report.service").read_text()
    rendered = sch.render_service("/opt/kevward/bin/kevward")

    def service(text):
        body = text.split("[Service]", 1)[1]
        return [ln for ln in body.splitlines() if ln and not ln.startswith("#")]

    assert service(example) == service(rendered)
    assert not any(ln.startswith(("ProtectHome", "PrivateTmp")) for ln in service(example))


def test_sandbox_detection(tmp_path):
    mi = tmp_path / "mountinfo"
    mi.write_text(
        "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
        "40 22 0:25 /systemd/inaccessible/dir /home ro,nosuid - tmpfs tmpfs rw\n"
        "41 22 8:1 /tmp/systemd-private-abc-kevward-report.service-x/tmp /tmp rw - ext4 "
        "/dev/sda1 rw\n")
    assert engine.report_sandbox(str(mi)) == {"home_hidden": True, "tmp_private": True}
    mi.write_text("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n")
    assert engine.report_sandbox(str(mi)) == {"home_hidden": False, "tmp_private": False}
    (f,) = engine.sandbox_findings({"home_hidden": True, "tmp_private": True})
    assert f.severity.value == "medium" and "/home and /tmp" in f.title
    assert engine.sandbox_findings({"home_hidden": False, "tmp_private": False}) == []


def test_gate_check_does_not_claim_missing_when_hidden():
    none = {"read": 0, "operate": 0, "sudoers": False, "checked": 1}
    (f,) = engine.gate_access_findings(True, none, False, home_hidden=True)
    assert f.severity.value == "info" and "could not be checked" in f.title
    (f,) = engine.gate_access_findings(True, none, False)
    assert f.severity.value == "medium" and "Checked 1 authorized_keys" in f.detail


def test_refresh_records_existing_blocklist(tmp_path, monkeypatch):
    r = Runner(table=True)
    env = _env(tmp_path, r)
    (tmp_path / "units").mkdir()
    (tmp_path / "units" / sch.SERVICE).write_text("[Service]\n")
    monkeypatch.setattr(sch, "is_root", lambda: True)
    monkeypatch.setattr(sch, "have", lambda c: False)
    su.setup(refresh=True, env=env)
    assert (tmp_path / "lib" / "firewall.json").exists()
    r2 = Runner(table=False)
    env2 = _env(tmp_path / "b", r2)
    (tmp_path / "b" / "units").mkdir(parents=True)
    (tmp_path / "b" / "units" / sch.SERVICE).write_text("[Service]\n")
    su.setup(refresh=True, env=env2)
    assert not (tmp_path / "b" / "lib" / "firewall.json").exists()
