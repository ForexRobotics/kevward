# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#229 / #247: automatic updaters under truthgate's enforce mode."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import updaters as up
from kevward.config import Config
from kevward.model import Severity
from kevward.util import BytesCmd, Cmd

NOW = datetime(2026, 11, 25, 3, 30, tzinfo=timezone.utc)


def tg(out=None, timed_out=False, missing=False):
    def check(p):
        if missing:
            from kevward.ssh_gate import GateError
            raise GateError("not_installed", "truthgate is not installed on this host")
        return "/usr/bin/truthgate"

    def runner(argv, input_, timeout, env, kill_grace=5.0):
        assert argv[-2:] == ["--role", "read"] and input_ == b'{"op":"truthgate.status"}'
        assert timeout <= up.STATUS_TIMEOUT_S
        return BytesCmd(124 if timed_out else 0, b"" if timed_out else out,
                        timed_out=timed_out)
    return up.truthgate_status(Config(), runner=runner, check=check)


def status(mode, maintenance=None):
    return (json.dumps({"ok": True, "data": {"mode": mode, "maintenance": maintenance,
                                             "agent_alive": True}}) + "\n").encode()


# --- apply_refusal --------------------------------------------------------------------

@pytest.mark.parametrize("st,refused", [
    (tg(missing=True), False),
    (tg(status(None)), False),                       # agent not running
    (tg(status("learn")), False),
    (tg(status("audit")), False),
    (tg(status("enforce", {"kind": "apply", "until": "x"})), False),
    (tg(status("enforce")), True),
    (tg(status("enforce", {"kind": "self_update"})), True),
    (tg(timed_out=True), True),                      # present but unreadable
    (tg(b"junk\n"), True),
    (tg(b'{"ok":false,"error":"x","code":"unavailable"}\n'), True),
])
def test_apply_refusal(st, refused):
    why = up.apply_refusal(st)
    assert bool(why) is refused
    if refused and st.get("readable"):
        assert "no maintenance window" in why


def test_record_and_report_refusal(tmp_path):
    p = tmp_path / "apply-refused.json"
    up.record_refusal("truthgate is enforcing", "systemd", NOW, path=p)
    rec = up.last_refusal(p)
    assert rec["source"] == "systemd"
    f = up.refused_findings(rec, NOW)
    assert f[0].severity == Severity.MEDIUM and "scheduled apply was refused" in f[0].title
    assert up.refused_findings(rec, NOW.replace(month=12, day=10)) == []
    assert up.refusal_source({"INVOCATION_ID": "x"}) == "systemd"
    assert up.refusal_source({}) == "cli"


def test_cli_apply_refused(monkeypatch, tmp_path, capsys):
    from kevward import cli

    monkeypatch.setattr(up, "truthgate_status",
                        lambda cfg: {"installed": True, "readable": True, "mode": "enforce",
                                     "maintenance": None, "error": ""})
    rec = []
    monkeypatch.setattr(up, "record_refusal", lambda why, src: rec.append((why, src)))
    ran = []
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: ran.append(1))
    cfg = tmp_path / "c.toml"
    cfg.write_text("")
    rc = cli.main(["apply", "-c", str(cfg), "--yes", "--reboot"])
    assert rc == up.EXIT_REFUSED and not ran and rec[0][1] == "cli"
    assert "no maintenance window" in capsys.readouterr().out


def test_job_refused(tmp_path, monkeypatch):
    from kevward import gate_apply as ga

    rec = []
    monkeypatch.setattr(up, "record_refusal", lambda why, src: rec.append(src))

    jobs = tmp_path / "jobs"
    jobs.mkdir()
    called = []
    rc = ga.run_job(Config(), expect="a" * 64, job_id=None, jobs_dir=jobs,
                    changes_file=tmp_path / "c.jsonl", engine_run=lambda *a, **k: called.append(1),
                    lock_path=tmp_path / "lock", redirect=False,
                    guard=lambda cfg: "truthgate is enforcing and no maintenance window is open")
    assert rc == up.EXIT_REFUSED and not called and rec == ["job"]


# --- unattended-upgrades --------------------------------------------------------------

def fake_run(uu_installed=True, periodic="1", uu_timer="active", apply_timer="disabled"):
    def run(argv, timeout=120, **kw):
        if argv[0] == "dpkg-query":
            return Cmd(0 if uu_installed else 1,
                       "install ok installed" if uu_installed else "", "")
        if argv[0] == "apt-config":
            return Cmd(0, f'APT::Periodic::Unattended-Upgrade "{periodic}";\n', "")
        if argv[1:] == ["is-active", "apt-daily-upgrade.timer"]:
            return Cmd(0 if uu_timer == "active" else 3, uu_timer + "\n", "")
        if argv[1:] == ["is-enabled", "kevward-apply.timer"]:
            return Cmd(0 if apply_timer == "enabled" else 1, apply_timer + "\n", "")
        raise AssertionError(argv)
    return run


def test_uu_state():
    assert up.uu_state(fake_run())["active"]
    assert not up.uu_state(fake_run(periodic="0"))["active"]
    assert not up.uu_state(fake_run(uu_installed=False))["active"]
    assert not up.uu_state(fake_run(uu_timer="inactive"))["active"]


def test_enforce_findings():
    enforce = {"mode": "enforce"}
    f = up.enforce_findings(enforce, {"active": True}, True)
    assert [x.severity for x in f] == [Severity.MEDIUM, Severity.MEDIUM]
    assert "two automatic updaters" in f[0].title and "kevward-apply.timer" in f[1].title
    assert up.enforce_findings({"mode": "audit"}, {"active": True}, True) == []


LOG = """\
2026-11-17 06:10:01,100 INFO Packages that will be upgraded: old-pkg
2026-11-20 06:10:01,100 INFO Packages that will be upgraded: libssl3 openssl
2026-11-25 01:10:01,100 INFO Packages that will be upgraded: tzdata
2026-11-25 01:10:02,100 INFO All upgrades installed
"""


def test_uu_installed_and_finding():
    done = up.uu_installed(LOG, NOW)
    assert done == {"day": ["tzdata"], "week": ["libssl3", "openssl", "tzdata"]}
    f = up.uu_findings(done)
    assert f[0].severity == Severity.INFO and "1 package(s) in the last 24 h, 3 in 7 days" \
        in f[0].title
    assert up.uu_findings({"day": [], "week": []}) == []


def test_host_findings(tmp_path):
    log = tmp_path / "uu.log"
    log.write_text(LOG)
    f = up.host_findings(Config(), NOW, run=fake_run(apply_timer="enabled"),
                         status={"mode": "enforce"}, uu_log=log,
                         refused=tmp_path / "none.json")
    assert {x.service for x in f} == {"kevward", "apt"} and len(f) == 3
    f = up.host_findings(Config(), NOW, run=fake_run(), status={"mode": None},
                         uu_log=tmp_path / "nope", refused=tmp_path / "none.json")
    assert f == []
