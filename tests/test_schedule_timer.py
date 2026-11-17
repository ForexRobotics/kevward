# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#69: `kevward schedule` owns the report timer. No systemd is touched."""

from __future__ import annotations

from kevward import cli
from kevward import schedule as sch
from kevward.util import Cmd


def _paths(tmp_path):
    return sch.Paths(unit_dir=tmp_path / "system", state_file=tmp_path / "lib" / "schedule.json")


def _fake_systemd(monkeypatch, calls):
    monkeypatch.setattr(sch, "is_root", lambda: True)
    monkeypatch.setattr(sch, "have", lambda n: True)
    monkeypatch.setattr(sch, "run", lambda args, **k: calls.append(args) or Cmd(0, "", ""))


def test_validate():
    assert sch.validate("07:00", "20min") is None
    assert sch.validate("7:00", "20min") and sch.validate("24:00", "1h")
    assert sch.validate("07:00", "20 minutes please")
    assert sch.validate("23:59", "900s") is None


def test_render_dropin_clears_base_calendar():
    d = sch.render_dropin("06:30", "20min")
    assert "OnCalendar=\nOnCalendar=*-*-* 06:30:00" in d
    assert "RandomizedDelaySec=20min" in d and "FixedRandomDelay=yes" in d


def test_service_keeps_tmp_and_home_visible_for_audit():
    s = sch.render_service("/usr/local/bin/kevward")
    assert "ExecStart=/usr/local/bin/kevward report --trends --audit" in s
    assert "PrivateTmp" not in s and "ProtectHome" not in s


def test_install_fresh_host_creates_all_and_records_state(tmp_path, monkeypatch):
    calls = []
    _fake_systemd(monkeypatch, calls)
    p = _paths(tmp_path)
    ok, msgs = sch.install("07:00", "20min", paths=p, exe="/usr/local/bin/kevward")
    assert ok, msgs
    assert p.service.exists() and p.timer.exists() and p.dropin.exists()
    import json
    created = json.loads(p.state_file.read_text())["created"]
    assert sorted(created) == sorted([str(p.service), str(p.timer)])
    assert calls[-1] == ["systemctl", "restart", "kevward-report.timer"]


def test_install_never_overwrites_hand_edited_units(tmp_path, monkeypatch):
    _fake_systemd(monkeypatch, [])
    p = _paths(tmp_path)
    p.unit_dir.mkdir(parents=True)
    p.service.write_text("# mine\n")
    p.timer.write_text("# mine too\n")
    other = p.unit_dir / "kevward-report.timer.d" / "10-local.conf"
    other.parent.mkdir()
    other.write_text("[Timer]\nPersistent=false\n")
    ok, _ = sch.install("06:00", "15min", paths=p, exe="/x")
    assert ok
    assert p.service.read_text() == "# mine\n" and p.timer.read_text() == "# mine too\n"
    assert "06:00" in p.dropin.read_text()
    # uninstall: only the drop-in goes; hand-made units and other drop-ins stay
    ok, msgs = sch.uninstall(paths=p)
    assert ok and not p.dropin.exists()
    assert p.service.exists() and p.timer.exists() and other.exists()
    assert any("not created by kevward" in m for m in msgs)


def test_uninstall_removes_what_install_created(tmp_path, monkeypatch):
    calls = []
    _fake_systemd(monkeypatch, calls)
    p = _paths(tmp_path)
    sch.install(paths=p, exe="/x")
    ok, _ = sch.uninstall(paths=p)
    assert ok and not p.service.exists() and not p.timer.exists() and not p.dropin.exists()
    assert ["systemctl", "disable", "--now", "kevward-report.timer"] in calls


def test_install_dry_run_and_non_root(tmp_path, monkeypatch):
    p = _paths(tmp_path)
    ok, msgs = sch.install(paths=p, exe="/x", dry_run=True)
    assert ok and msgs[0].startswith("DRY RUN") and not p.unit_dir.exists()
    monkeypatch.setattr(sch, "is_root", lambda: False)
    ok, msgs = sch.install(paths=p, exe="/x")
    assert not ok and "root" in msgs[0]


SHOW = """TimersCalendar={ OnCalendar=*-*-* 07:00:00 ; next_elapse=Thu 2026-11-19 07:00:00 JST }
RandomizedDelayUSec=0
FixedRandomDelay=no
NextElapseUSecRealtime=Thu 2026-11-19 07:00:00 JST
LastTriggerUSec=Wed 2026-11-18 07:00:01 JST
UnitFileState=enabled
ActiveState=active
"""


def test_status_parsing_and_warnings():
    props = sch.parse_show(SHOW)
    assert sch.calendar_of(props["TimersCalendar"]) == "*-*-* 07:00:00"
    warns = sch.status_warnings(props, dropin_exists=False)
    assert any("no random delay" in w for w in warns)
    assert any("drop-in" in w for w in warns)
    good = dict(props, RandomizedDelayUSec="20min", FixedRandomDelay="yes")
    assert sch.status_warnings(good, dropin_exists=True) == []


def test_cli_install_without_yes_is_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(sch, "kevward_exe", lambda: "/usr/local/bin/kevward")
    assert cli.main(["schedule", "install", "--at", "06:45"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("DRY RUN") and "OnCalendar=*-*-* 06:45:00" in out
    assert cli.main(["schedule", "install", "--at", "6:45"]) == 1
