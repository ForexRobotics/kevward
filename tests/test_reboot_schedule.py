# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#114: show whether a reboot is scheduled; --status / --cancel; exit codes.
Never calls shutdown for real."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kevward import cli, scheduler
from kevward.util import Cmd

# 2026-11-13 21:00 JST = 12:00 UTC (the hokaku3 reboot of 11/13).
USEC = int(datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)
FILE = f"USEC={USEC}\nWARN_WALL=1\nMODE=reboot\nWALL_MESSAGE=kevward maintenance\n"


def test_parse_scheduled_file():
    when, mode = scheduler.parse_scheduled(FILE)
    assert when == datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc) and mode == "reboot"
    assert scheduler.parse_scheduled("MODE=reboot\n") is None
    assert scheduler.parse_scheduled("USEC=0\n") is None
    assert scheduler.parse_scheduled("") is None


def test_parse_busctl():
    got = scheduler.parse_busctl_scheduled(f'(st) "reboot" {USEC}\n')
    assert got and got[1] == "reboot"
    assert scheduler.parse_busctl_scheduled('(st) "" 0\n') is None


def test_scheduled_reboot_file_present_absent_unreadable(tmp_path, monkeypatch):
    f = tmp_path / "scheduled"
    f.write_text(FILE)
    st = scheduler.scheduled_reboot(str(f))
    assert st == {"state": "scheduled", "at": "2026-11-13T12:00:00+00:00", "mode": "reboot"}
    assert scheduler.scheduled_reboot(str(tmp_path / "missing")) == {"state": "none"}
    # unreadable (a directory here) and no busctl -> unknown
    monkeypatch.setattr(scheduler, "have", lambda n: False)
    assert scheduler.scheduled_reboot(str(tmp_path)) == {"state": "unknown"}
    # unreadable but logind answers
    monkeypatch.setattr(scheduler, "have", lambda n: n == "busctl")
    monkeypatch.setattr(scheduler, "run", lambda *a, **k: Cmd(0, f'(st) "reboot" {USEC}', ""))
    assert scheduler.scheduled_reboot(str(tmp_path))["state"] == "scheduled"


def test_describe():
    assert scheduler.describe({"state": "none"}) == "none"
    assert scheduler.describe({"state": "unknown"}) == "unknown"
    s = scheduler.describe({"state": "scheduled", "at": "2026-11-13T12:00:00+00:00",
                            "mode": "poweroff"})
    assert s.endswith("(poweroff)") and s.startswith("2026-11-1")


def test_schedule_failure_is_nonzero(monkeypatch):
    monkeypatch.setattr(scheduler, "is_root", lambda: True)
    monkeypatch.setattr(scheduler, "have", lambda n: True)
    monkeypatch.setattr(scheduler, "run",
                        lambda *a, **k: Cmd(1, "", "Failed to call ScheduleShutdown"))
    ok, msg = scheduler.schedule_reboot("03:00")
    assert not ok and "Failed to call" in msg


def test_cancel_path(monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler, "is_root", lambda: True)
    monkeypatch.setattr(scheduler, "have", lambda n: True)
    monkeypatch.setattr(scheduler, "scheduled_reboot", lambda path=None: {"state": "scheduled"})
    monkeypatch.setattr(scheduler, "run", lambda args, **k: calls.append(args) or Cmd(0, "", ""))
    assert scheduler.cancel_reboot() == (True, "scheduled reboot cancelled")
    assert calls == [["shutdown", "-c"]]
    monkeypatch.setattr(scheduler, "is_root", lambda: False)
    assert scheduler.cancel_reboot()[0] is False


def test_cli_status_is_read_only(monkeypatch, capsys):
    monkeypatch.setattr(scheduler, "scheduled_reboot",
                        lambda path=None: {"state": "scheduled",
                                           "at": "2026-11-13T12:00:00+00:00", "mode": "reboot"})
    monkeypatch.setattr(scheduler, "cancel_reboot", lambda: (_ for _ in ()).throw(AssertionError))
    assert cli.main(["schedule-reboot", "--status"]) == 0
    assert capsys.readouterr().out.startswith("reboot scheduled: 2026-11-1")
    assert cli.main(["schedule-reboot", "--status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "scheduled"


def test_cli_cancel_exit_codes(monkeypatch):
    monkeypatch.setattr(scheduler, "cancel_reboot", lambda: (True, "scheduled reboot cancelled"))
    assert cli.main(["schedule-reboot", "--cancel"]) == 0
    monkeypatch.setattr(scheduler, "cancel_reboot", lambda: (False, "skipped: requires root"))
    assert cli.main(["schedule-reboot", "--cancel"]) == 1


def test_report_header_and_json():
    from kevward.engine import RunResult
    from kevward.reporting.html import render
    r = RunResult(host="hokaku3", generated_at="2026-11-13T00:00:00+00:00", os="Ubuntu 22.04",
                  reboot_schedule={"state": "scheduled", "at": "2026-11-13T12:00:00+00:00",
                                   "mode": "reboot"})
    assert r.to_dict()["reboot_scheduled"] == "2026-11-13T12:00:00+00:00"
    assert "reboot scheduled: <b>2026-11-1" in render(r)
    r.reboot_schedule = {"state": "none"}
    assert r.to_dict()["reboot_scheduled"] is None
    assert "reboot scheduled: <b>none</b>" in render(r)
