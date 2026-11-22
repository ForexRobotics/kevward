# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#198 reboot.* and #199 schedule.* over ssh-gate, without root."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import engine, gate_ops, scheduler, util
from kevward import schedule as sch
from kevward import ssh_gate as g
from kevward.util import Cmd

NOW = datetime(2026, 11, 22, 1, 0, 0, tzinfo=timezone.utc)
BASE = """[ssh_gate]
enabled = true

[policy]
allow_reboot = {allow}
"""


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(BASE.format(allow="true"))
    return path, tmp_path / "changes.jsonl"


class Shutdown:
    """Fake ``shutdown`` plus the state scheduled_reboot() would read."""

    def __init__(self, monkeypatch, state=None, rc=0):
        self.calls: list[list[str]] = []
        self.state = state or {"state": "none"}
        self.rc = rc
        monkeypatch.setattr(scheduler, "scheduled_reboot", lambda *a, **k: dict(self.state))

    def __call__(self, args, timeout=0, **_k):
        self.calls.append(args)
        return Cmd(rc=self.rc, out="", err="boom" if self.rc else "")


def call(env, req, role="operate", **opts):
    path, changes = env
    resp = g.handle(json.dumps(req).encode(), role, path=path, changes_file=changes,
                    client="203.0.113.5", now=NOW, op_opts=opts)
    assert set(json.loads(g.dumps(resp))) in ({"ok", "data"}, {"ok", "error", "code"})
    return resp


def records(env):
    _, changes = env
    return [json.loads(x) for x in changes.read_text().splitlines()] if changes.exists() else []


# --- roles ---------------------------------------------------------------------------

def test_ops_by_role(env):
    v = call(env, {"op": "version"}, role="read")["data"]["ops"]
    assert "reboot.status" in v and "schedule.status" in v
    assert "reboot.schedule" not in v and "schedule.install" not in v
    for op in ("reboot.schedule", "reboot.cancel", "schedule.install"):
        assert call(env, {"op": op}, role="read")["code"] == "forbidden"


# --- reboot.status -------------------------------------------------------------------

def test_reboot_status_host_and_gate(env, monkeypatch):
    monkeypatch.setattr(util, "reboot_pending", lambda: True)
    monkeypatch.setattr(util, "reboot_pending_pkgs", lambda: ["linux-image-6.8.0-90"])
    monkeypatch.setattr(util, "reboot_kind", lambda pkgs: "kernel")
    sd = Shutdown(monkeypatch)
    d = call(env, {"op": "reboot.status"}, role="read")["data"]
    assert d["scheduled"] == {"state": "none"} and d["set_by"] is None
    assert d["required"] and d["packages"] == ["linux-image-6.8.0-90"] and d["kind"] == "kernel"

    sd.state = {"state": "scheduled", "at": "2026-11-22T18:00:00+00:00", "mode": "reboot"}
    assert call(env, {"op": "reboot.status"})["data"]["set_by"] == {"via": "host"}

    sd.state = {"state": "none"}
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-23T03:00+09:00",
                                                     "reason": "kernel 6.8.0-90"}}, runner=sd)
    sd.state = dict(r["data"]["scheduled"])
    by = call(env, {"op": "reboot.status"})["data"]["set_by"]
    assert by["via"] == "ssh-gate" and by["client"] == "203.0.113.5"
    assert by["reason"] == "kernel 6.8.0-90"


# --- reboot.schedule -----------------------------------------------------------------

def test_reboot_schedule(env, monkeypatch):
    sd = Shutdown(monkeypatch)
    r = call(env, {"op": "reboot.schedule",
                   "args": {"at": "2026-11-23T03:00+09:00", "reason": "kernel"}}, runner=sd)
    assert r["ok"], r
    # 2026-11-22T18:00Z is 17 h after NOW
    assert sd.calls == [["shutdown", "-r", "+1020", "kevward (ssh-gate): kernel"]]
    assert r["data"]["scheduled"]["at"] == "2026-11-22T18:00:00+00:00"
    assert r["data"]["replaced"] is False
    rec = records(env)[-1]
    assert rec["kind"] == "reboot.schedule" and rec["client"] == "203.0.113.5"
    assert rec["at"] == "2026-11-22T18:00:00+00:00"


def test_reboot_schedule_z_and_rounding_up(env, monkeypatch):
    sd = Shutdown(monkeypatch)
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-22T01:10:30Z"}}, runner=sd)
    assert r["ok"] and sd.calls[0][:3] == ["shutdown", "-r", "+11"]  # never early
    assert sd.calls[0][3] == "kevward (ssh-gate)"


@pytest.mark.parametrize("at,word", [
    ("2026-11-22T01:04:00Z", "5 minutes"),       # too soon
    ("2026-11-21T00:00:00Z", "5 minutes"),       # past
    ("2026-11-29T01:00:01Z", "7 days"),          # too far
    ("2026-11-23T03:00", "offset"),              # naive
    ("tomorrow", "ISO 8601"),
    (1732300000, "ISO 8601"),
])
def test_reboot_schedule_bad_time(env, monkeypatch, at, word):
    sd = Shutdown(monkeypatch)
    r = call(env, {"op": "reboot.schedule", "args": {"at": at}}, runner=sd)
    assert r["code"] == "bad_request" and word in r["error"] and not sd.calls


@pytest.mark.parametrize("args", [
    {"reason": "x" * 81}, {"reason": "a\nb"}, {"reason": "$(id)"}, {"reason": 3},
    {"replace": "yes"},
])
def test_reboot_schedule_bad_args(env, monkeypatch, args):
    sd = Shutdown(monkeypatch)
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-22T12:00Z", **args}},
             runner=sd)
    assert r["code"] == "bad_request" and not sd.calls


def test_reboot_schedule_needs_host_policy(env, monkeypatch):
    path, _ = env
    path.write_text(BASE.format(allow="false"))
    sd = Shutdown(monkeypatch)
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-22T12:00Z"}}, runner=sd)
    assert r["code"] == "forbidden" and "allow_reboot" in r["error"] and not sd.calls


def test_reboot_schedule_conflict_and_replace(env, monkeypatch):
    old = {"state": "scheduled", "at": "2026-11-22T10:00:00+00:00", "mode": "reboot"}
    sd = Shutdown(monkeypatch, state=old)
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-22T12:00Z"}}, runner=sd)
    assert r["code"] == "conflict" and "replace" in r["error"] and not sd.calls
    r = call(env, {"op": "reboot.schedule",
                   "args": {"at": "2026-11-22T12:00Z", "replace": True}}, runner=sd)
    assert r["ok"] and r["data"]["replaced"] is True
    assert records(env)[-1]["replaced"] == old


def test_reboot_schedule_shutdown_fails(env, monkeypatch):
    sd = Shutdown(monkeypatch, rc=1)
    r = call(env, {"op": "reboot.schedule", "args": {"at": "2026-11-22T12:00Z"}}, runner=sd)
    assert r["code"] == "internal" and "boom" in r["error"] and records(env) == []


# --- reboot.cancel -------------------------------------------------------------------

def test_reboot_cancel(env, monkeypatch):
    sd = Shutdown(monkeypatch)
    assert call(env, {"op": "reboot.cancel"}, runner=sd)["code"] == "not_found"
    assert not sd.calls
    sd.state = {"state": "scheduled", "at": "2026-11-22T10:00:00+00:00", "mode": "reboot"}
    r = call(env, {"op": "reboot.cancel"}, runner=sd)
    assert r["ok"] and sd.calls == [["shutdown", "-c"]]
    assert r["data"]["cancelled"]["at"] == "2026-11-22T10:00:00+00:00"
    assert records(env)[-1]["kind"] == "reboot.cancel"


# --- schedule.* (#199) ---------------------------------------------------------------

def test_schedule_status(env, monkeypatch):
    props = {"TimersCalendar": "{ OnCalendar=*-*-* 07:00:00 ; next_elapse=n/a }",
             "UnitFileState": "enabled"}
    monkeypatch.setattr(sch, "status", lambda paths=None: (props, ["w1"]))
    d = call(env, {"op": "schedule.status"}, role="read")["data"]
    assert d == {"timer": props, "calendar": "*-*-* 07:00:00", "warnings": ["w1"]}


def test_schedule_install(env, monkeypatch):
    seen = {}

    def fake(*a, paths=None, **k):
        seen["paths"] = paths
        return True, ["created /x/kevward.timer"]

    monkeypatch.setattr(sch, "install", fake)
    r = call(env, {"op": "schedule.install"}, paths="P")
    assert r["ok"] and r["data"]["messages"] == ["created /x/kevward.timer"]
    assert seen["paths"] == "P" and records(env)[-1]["kind"] == "schedule.install"

    monkeypatch.setattr(sch, "install", lambda *a, **k: (False, ["needs root"]))
    r = call(env, {"op": "schedule.install"})
    assert r["code"] == "internal" and "needs root" in r["error"]


# --- the report shows what the gate did ----------------------------------------------

def test_findings_for_phase2_records():
    recs = [
        {"kind": "reboot.schedule", "time": "t1", "client": "c", "at": "A", "reason": "k"},
        {"kind": "reboot.cancel", "time": "t2", "client": "c", "was": {"at": "A"}},
        {"kind": "schedule.install", "time": "t3", "client": "c"},
    ]
    f = engine.gate_change_findings(recs)
    assert [x.title for x in f] == [
        "reboot scheduled for A via ssh-gate at t1 from c",
        "scheduled reboot cancelled via ssh-gate at t2 from c",
        "report timer (re)installed via ssh-gate at t3 from c",
    ]
    assert f[0].detail.startswith("Reason: k.") and "Was: A" in f[1].detail


def test_reason_charset():
    assert gate_ops._REASON.match("kernel 6.8.0-90 (USN-7000-1)")
    assert gate_ops._REASON.match("再起動: カーネル更新")
    assert not gate_ops._REASON.match("a;b`c")
