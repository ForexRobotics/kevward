# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#240: rebuild the report after an apply; ssh-gate report.refresh; last_apply."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from test_ssh_gate_apply import BASE, FINDINGS, NOW, FakeEngine, start

from kevward import gate_apply as ga
from kevward import schedule as sch
from kevward import ssh_gate as g
from kevward.config import Config
from kevward.util import Cmd


class Systemctl:
    def __init__(self, active="inactive", rc=0):
        self.calls, self.active, self.rc = [], active, rc

    def __call__(self, argv, timeout=0, **_k):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "is-active"]:
            return Cmd(0, self.active + "\n", "")
        if argv[:1] == ["systemctl"]:
            return Cmd(self.rc, "", "Failed to restart" if self.rc else "")
        return Cmd(0, "", "")


@pytest.fixture
def env(tmp_path, monkeypatch):
    import kevward.util as util

    path = tmp_path / "config.toml"
    path.write_text(BASE)
    monkeypatch.setattr(util, "is_root", lambda: True)
    return {"path": path, "changes": tmp_path / "changes.jsonl", "jobs": tmp_path / "jobs"}


@pytest.fixture
def unit(tmp_path):
    paths = sch.Paths(unit_dir=tmp_path / "units", state_file=tmp_path / "s.json")
    paths.service.parent.mkdir()
    paths.service.write_text("[Service]\n")
    return paths


# --- A: end of an apply job ------------------------------------------------------

def _run(env, unit, sysctl, findings=FINDINGS, fail=False):
    h, jid = start(env, findings)
    cfg = Config.load(env["path"])
    ga.run_job(cfg, expect=h, job_id=jid, jobs_dir=env["jobs"], changes_file=env["changes"],
               engine_run=FakeEngine(findings, fail=fail), runner=sysctl,
               lock_path=env["jobs"] / "lock", redirect=False, now_fn=lambda: NOW,
               reboot_pending=lambda: False, report_paths=unit)
    return json.loads((env["jobs"] / f"{jid}.json").read_text())


def test_job_restarts_report_when_installed(env, unit):
    sysctl = Systemctl(active="active")
    job = _run(env, unit, sysctl)
    assert ["systemctl", "restart", "--no-block", sch.SERVICE] in sysctl.calls
    assert job["state"] == "succeeded" and job["result"]["report_refresh"] == "started"


def test_job_failed_install_does_not_refresh(env, unit):
    # FakeEngine(fail=True) fails the only install action: nothing was installed
    sysctl = Systemctl()
    job = _run(env, unit, sysctl, fail=True)
    assert job["result"]["report_refresh"] == "skipped" and sysctl.calls == []


def test_job_nothing_installed_or_no_unit(env, unit, tmp_path):
    sysctl = Systemctl()
    job = _run(env, unit, sysctl, findings=[])
    assert job["result"]["report_refresh"] == "skipped" and sysctl.calls == []
    unit.service.unlink()
    job = _run(env, unit, sysctl)
    assert job["result"]["report_refresh"] == "skipped"


def test_job_systemctl_error_does_not_fail_job(env, unit):
    job = _run(env, unit, Systemctl(rc=1))
    assert job["state"] == "succeeded"
    assert job["result"]["report_refresh"] == {"error": "Failed to restart"}


# --- B: report.refresh -----------------------------------------------------------

def call(env, unit, sysctl, role="operate", now=NOW):
    rep = env["path"].parent / "rep"
    rep.mkdir(exist_ok=True)
    (rep / "report.json").write_text('{"generated_at": "2026-11-21T22:05:00+00:00"}')
    env["path"].write_text(f'report_dir = "{rep}"\n[ssh_gate]\nenabled = true\n')
    return g.handle(b'{"op":"report.refresh"}', role, path=env["path"],
                    changes_file=env["changes"], client="203.0.113.5", now=now,
                    op_opts={"runner": sysctl, "paths": unit})


def test_report_refresh(env, unit):
    sysctl = Systemctl()
    r = call(env, unit, sysctl)
    assert r["ok"] and r["data"] == {"started": True, "running": False,
                                     "unit": sch.SERVICE,
                                     "previous_generated_at": "2026-11-21T22:05:00+00:00"}
    assert ["systemctl", "start", "--no-block", sch.SERVICE] in sysctl.calls
    rec = json.loads(env["changes"].read_text().splitlines()[-1])
    assert rec["kind"] == "report.refresh" and rec["client"] == "203.0.113.5"
    # too soon
    r = call(env, unit, sysctl, now=NOW + timedelta(seconds=60))
    assert r["code"] == "conflict" and "240 s" in r["error"]
    assert call(env, unit, sysctl, now=NOW + timedelta(seconds=301))["ok"]


def test_report_refresh_running_unit_and_roles(env, unit):
    r = call(env, unit, Systemctl(active="activating"))
    assert r["ok"] and r["data"]["started"] is False and r["data"]["running"] is True
    assert call(env, unit, Systemctl(), role="read")["code"] == "forbidden"
    unit.service.unlink()
    assert call(env, unit, Systemctl())["code"] == "not_found"
    v = g.handle(b'{"op":"version"}', "operate", path=env["path"])["data"]["ops"]
    assert "report.refresh" in v


def test_interval_config():
    assert Config.from_dict({"ssh_gate": {"report_refresh_min_interval_s": 0}})
    with pytest.raises(ValueError):
        Config.from_dict({"ssh_gate": {"report_refresh_min_interval_s": -1}})


# --- C: last_apply ---------------------------------------------------------------

def test_last_apply(tmp_path):
    jobs = tmp_path / "jobs"
    assert ga.last_apply(jobs) is None
    ga.write_job(jobs, {"job_id": "20261124T010000Z-aaaaaa", "state": "succeeded",
                        "finished": "2026-11-24T01:01:00+00:00",
                        "result": {"installed": ["a", "b"]}})
    ga.write_job(jobs, {"job_id": "20261124T020000Z-bbbbbb", "state": "running"})
    assert ga.last_apply(jobs) == {"job_id": "20261124T010000Z-aaaaaa",
                                   "finished": "2026-11-24T01:01:00+00:00",
                                   "state": "succeeded", "installed_count": 2}
    from kevward.engine import RunResult
    from kevward.reporting.data import report_data
    d = report_data(RunResult(host="h", generated_at="t", os="Linux"), jobs_dir=jobs)
    assert d["last_apply"]["installed_count"] == 2
    assert datetime.fromisoformat(d["last_apply"]["finished"]).tzinfo == timezone.utc


def test_report_html_written_atomically(tmp_path, monkeypatch):
    import stat

    from kevward import cli
    from kevward.engine import RunResult

    cfg = tmp_path / "c.toml"
    cfg.write_text("[update]\ncheck = false\n")
    monkeypatch.setattr(cli, "run_engine",
                        lambda *a, **k: RunResult(host="h", generated_at="t", os="Linux"))
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: {})
    out = tmp_path / "report.html"
    out.write_text("old")
    seen = []
    real = type(out).replace

    def spy(self, target):
        seen.append((self.name, getattr(target, "name", str(target))))
        return real(self, target)

    monkeypatch.setattr(type(out), "replace", spy)
    assert cli.main(["report", "-c", str(cfg), "-o", str(out)]) == 0
    assert (".report.html.tmp", "report.html") in seen
    assert out.read_text().startswith("<!doctype html>")
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    assert not list(tmp_path.glob(".*.tmp"))
