# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#197: plan / apply.start / job.get over ssh-gate, with a fake engine and a
fake systemd-run, without root."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import engine, scheduler
from kevward import gate_apply as ga
from kevward import ssh_gate as g
from kevward.config import Config
from kevward.engine import RunResult
from kevward.model import ActionResult, Finding, FindingKind, ServiceReport, Severity
from kevward.util import Cmd

NOW = datetime(2026, 11, 22, 1, 0, 0, tzinfo=timezone.utc)
BASE = """[ssh_gate]
enabled = true

[policy]
allow_reboot = true
"""


def finding(pkg, kind=FindingKind.SECURITY_UPDATE, frm="1.0", to="1.1",
            origin="Ubuntu:24.04/noble-security", reboot=False):
    return Finding(service="apt", kind=kind, severity=Severity.HIGH, title=pkg,
                   current_version=frm, fixed_version=to, ref=pkg, origin=origin,
                   reboot_required=reboot)


class FakeEngine:
    """engine.run stand-in: findings per run; apply installs the security ones
    (minor ones only when the policy says so), like the real plugins."""

    def __init__(self, findings, fail=False):
        self.findings = findings
        self.fail = fail
        self.calls: list[dict] = []

    def __call__(self, cfg, do_apply=False, dry_run=True, fresh=True):
        self.calls.append({"dry_run": dry_run, "fresh": fresh})
        sp = cfg.policy
        act = sorted(f.ref for f in self.findings
                     if (f.kind == FindingKind.SECURITY_UPDATE and sp.apply_security)
                     or (f.kind == FindingKind.MINOR_UPGRADE and sp.apply_minor))
        actions = []
        if do_apply and act:
            actions = [ActionResult("apt", "install: " + ", ".join(act), dry_run=dry_run,
                                    changed=not dry_run, ok=not (self.fail and not dry_run),
                                    output="E: boom" if self.fail else "",
                                    reboot_required=any(f.reboot_required
                                                        for f in self.findings))]
        return RunResult(host="h", generated_at="2026-11-22T01:00:00+00:00", os="Linux",
                         services=[ServiceReport("apt", True, findings=list(self.findings),
                                                 actions=actions)],
                         apt_refresh={"state": "ok", "seconds": 2})


FINDINGS = [finding("openssl"), finding("libc6", reboot=True),
            finding("curl", kind=FindingKind.MINOR_UPGRADE, origin="Ubuntu:24.04/noble-updates")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(BASE)
    jobs = tmp_path / "jobs"
    monkeypatch.setattr(ga, "is_root", lambda: True, raising=False)
    import kevward.util as util
    monkeypatch.setattr(util, "is_root", lambda: True)
    return {"path": path, "changes": tmp_path / "changes.jsonl", "jobs": jobs}


def call(env, req, role="operate", **opts):
    opts.setdefault("jobs_dir", env["jobs"])
    resp = g.handle(json.dumps(req).encode(), role, path=env["path"],
                    changes_file=env["changes"], client="203.0.113.5", now=NOW, op_opts=opts)
    assert set(json.loads(g.dumps(resp))) in ({"ok", "data"}, {"ok", "error", "code"})
    return resp


def compute_with(fake):
    return lambda cfg: ga.compute_plan(cfg, engine_run=fake)


class Launcher:
    def __init__(self, rc=0):
        self.argv = None
        self.rc = rc

    def __call__(self, argv, timeout=0, **_k):
        self.argv = argv
        return Cmd(rc=self.rc, out="", err="Failed to start" if self.rc else "")


# --- plan ------------------------------------------------------------------------

def test_plan(env):
    d = call(env, {"op": "plan"}, role="read", compute=compute_with(FakeEngine(FINDINGS)))["data"]
    assert [i["package"] for i in d["items"]] == ["libc6", "openssl"]
    assert d["items"][1] == {"package": "openssl", "service": "apt", "from": "1.0", "to": "1.1",
                             "kind": "security", "origin": "Ubuntu:24.04/noble-security"}
    assert d["skipped"] == [{"package": "curl", "service": "apt", "from": "1.0", "to": "1.1",
                             "kind": "minor", "origin": "Ubuntu:24.04/noble-updates",
                             "reason": "apply_minor is off"}]
    assert d["reboot_expected"] is True and len(d["plan_hash"]) == 64
    assert d["policy"]["apply_minor"] is False and d["as_root"] is True
    assert d["apt_refresh"]["state"] == "ok" and d["generated_at"]


def test_plan_read_role_not_root(env, monkeypatch):
    import kevward.util as util
    monkeypatch.setattr(util, "is_root", lambda: False)
    d = call(env, {"op": "plan"}, role="read", compute=compute_with(FakeEngine(FINDINGS)))["data"]
    assert d["as_root"] is False


def test_plan_empty_has_hash(env):
    d = call(env, {"op": "plan"}, compute=compute_with(FakeEngine([])))["data"]
    assert d["items"] == [] and len(d["plan_hash"]) == 64 and d["reboot_expected"] is False


def test_hash_stable_and_ordered():
    pol = ga.plan_policy(Config())
    a = [{"package": "b", "from": "1", "to": "2", "origin": "o", "kind": "security",
          "service": "apt"},
         {"package": "a", "from": "1", "to": "2", "origin": "o", "kind": "security",
          "service": "nginx"}]
    h = ga.plan_hash(a, pol)
    assert h == ga.plan_hash(list(reversed(a)), pol)            # order-free
    assert h == ga.plan_hash([{**a[0], "service": "x"}, a[1]], pol)  # service is display only
    assert h != ga.plan_hash([{**a[0], "to": "3"}, a[1]], pol)   # a version moved
    assert h != ga.plan_hash(a, {**pol, "apply_minor": True})     # policy changed
    assert h == f"{int(h, 16):064x}"


def test_plan_does_not_print(env, capsys):
    class Noisy(FakeEngine):
        def __call__(self, *a, **k):
            print("chatter")
            return super().__call__(*a, **k)

    ga.compute_plan(Config(), engine_run=Noisy(FINDINGS))
    assert capsys.readouterr().out == ""


# --- apply.start -----------------------------------------------------------------

def plan_hash_for(env, findings=FINDINGS):
    r = call(env, {"op": "plan"}, compute=compute_with(FakeEngine(findings)))
    return r["data"]["plan_hash"]


def test_apply_start(env):
    h = plan_hash_for(env)
    la = Launcher()
    r = call(env, {"op": "apply.start", "args": {"expect_plan": h}},
             compute=compute_with(FakeEngine(FINDINGS)), launcher=la, busy=lambda: None)
    assert r["ok"], r
    jid = r["data"]["job_id"]
    assert ga._JOB_ID.match(jid) and jid.startswith("20261122T010000Z-")
    assert la.argv[:3] == ["systemd-run", f"--unit=kevward-apply-{jid}", "--collect"]
    tail = la.argv[la.argv.index("apply"):]
    assert tail == ["apply", "-c", str(env["path"]), "--yes", "--expect-plan", h,
                    "--job", jid]
    job = json.loads((env["jobs"] / f"{jid}.json").read_text())
    assert job["state"] == "starting" and job["packages"] == ["libc6", "openssl"]
    assert job["client"] == "203.0.113.5" and job["reboot"] == {"mode": "never"}
    rec = json.loads(env["changes"].read_text().splitlines()[-1])
    assert rec["kind"] == "apply.start" and rec["job_id"] == jid


def test_apply_start_conflict_on_changed_plan(env):
    h = plan_hash_for(env)
    moved = [finding("openssl", to="1.2"), *FINDINGS[1:]]
    la = Launcher()
    r = call(env, {"op": "apply.start", "args": {"expect_plan": h}},
             compute=compute_with(FakeEngine(moved)), launcher=la, busy=lambda: None)
    assert r["code"] == "conflict" and plan_hash_for(env, moved) in r["error"]
    assert la.argv is None and not env["jobs"].exists()


@pytest.mark.parametrize("args", [
    {"expect_plan": "a" * 64, "minor": True},
    {"expect_plan": "a" * 64, "apply_minor": True},
    {"expect_plan": "a" * 64, "policy": {"apply_minor": True}},
])
def test_policy_not_overridable(env, args):
    la = Launcher()
    r = call(env, {"op": "apply.start", "args": args},
             compute=compute_with(FakeEngine(FINDINGS)), launcher=la, busy=lambda: None)
    assert r["code"] == "bad_request" and "host" in r["error"] and la.argv is None


@pytest.mark.parametrize("args", [{}, {"expect_plan": "xyz"}, {"expect_plan": "A" * 64}])
def test_apply_start_bad_hash(env, args):
    r = call(env, {"op": "apply.start", "args": args}, busy=lambda: None)
    assert r["code"] == "bad_request"


def test_apply_start_busy(env):
    h = plan_hash_for(env)
    r = call(env, {"op": "apply.start", "args": {"expect_plan": h}},
             compute=compute_with(FakeEngine(FINDINGS)), launcher=Launcher(),
             busy=lambda: "apt/dpkg is running")
    assert r == {"ok": False, "code": "conflict", "error": "apt/dpkg is running"}


def test_busy_reason_running_job_and_lock(env, tmp_path):
    import fcntl

    jobs = env["jobs"]
    ga.write_job(jobs, {"job_id": "20261122T000000Z-abcdef", "state": "running"})
    lock = tmp_path / "self-update.lock"
    apt = tmp_path / "lock-frontend"
    apt.write_text("")
    assert "still running" in ga.busy_reason(jobs, unit_active=lambda u: True,
                                             lock_path=lock, apt_lock=apt)
    assert ga.busy_reason(jobs, unit_active=lambda u: False, lock_path=lock,
                          apt_lock=apt) is None
    with open(lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        assert "self.update" in ga.busy_reason(jobs, unit_active=lambda u: False,
                                               lock_path=lock, apt_lock=apt)


def test_apply_start_not_root(env, monkeypatch):
    import kevward.util as util
    monkeypatch.setattr(util, "is_root", lambda: False)
    h = plan_hash_for(env)
    r = call(env, {"op": "apply.start", "args": {"expect_plan": h}},
             compute=compute_with(FakeEngine(FINDINGS)), launcher=Launcher(), busy=lambda: None)
    assert r["code"] == "forbidden"


def test_apply_start_read_role(env):
    assert call(env, {"op": "apply.start", "args": {"expect_plan": "a" * 64}},
                role="read")["code"] == "forbidden"


def test_apply_start_reboot(env):
    h = plan_hash_for(env)
    la = Launcher()
    r = call(env, {"op": "apply.start", "args": {
        "expect_plan": h, "reboot": {"mode": "if_required", "at": "2026-11-23T03:00+09:00"}}},
        compute=compute_with(FakeEngine(FINDINGS)), launcher=la, busy=lambda: None)
    assert r["ok"] and r["data"]["reboot"] == {"mode": "if_required",
                                               "at": "2026-11-22T18:00:00+00:00"}
    assert la.argv[-2:] == ["--reboot-at", "2026-11-22T18:00:00+00:00"]


@pytest.mark.parametrize("reboot,code", [
    ({"mode": "now"}, "bad_request"),
    ({"mode": "if_required"}, "bad_request"),
    ({"mode": "if_required", "at": "2026-11-22T01:01Z"}, "bad_request"),
    ("if_required", "bad_request"),
])
def test_apply_start_bad_reboot(env, reboot, code):
    r = call(env, {"op": "apply.start", "args": {"expect_plan": "a" * 64, "reboot": reboot}},
             busy=lambda: None)
    assert r["code"] == code


def test_apply_start_reboot_needs_policy(env):
    env["path"].write_text("[ssh_gate]\nenabled = true\n")
    r = call(env, {"op": "apply.start", "args": {
        "expect_plan": "a" * 64, "reboot": {"mode": "if_required", "at": "2026-11-22T12:00Z"}}},
        busy=lambda: None)
    assert r["code"] == "forbidden" and "allow_reboot" in r["error"]


def test_apply_start_systemd_run_fails(env):
    h = plan_hash_for(env)
    r = call(env, {"op": "apply.start", "args": {"expect_plan": h}},
             compute=compute_with(FakeEngine(FINDINGS)), launcher=Launcher(rc=1),
             busy=lambda: None)
    assert r["code"] == "internal"
    (job,) = [json.loads(p.read_text()) for p in env["jobs"].glob("*.json")]
    assert job["state"] == "failed" and "Failed to start" in job["error"]


# --- the job and job.get ---------------------------------------------------------

def start(env, findings=FINDINGS, **reboot):
    h = plan_hash_for(env, findings)
    args = {"expect_plan": h}
    if reboot:
        args["reboot"] = reboot
    r = call(env, {"op": "apply.start", "args": args},
             compute=compute_with(FakeEngine(findings)), launcher=Launcher(), busy=lambda: None)
    return h, r["data"]["job_id"]


def job(env, jid, active=True):
    return call(env, {"op": "job.get", "args": {"job_id": jid}}, role="read",
                unit_active=lambda u: active)


def run_job(env, h, jid, fake, **kw):
    cfg = Config.load(env["path"])
    return ga.run_job(cfg, expect=h, job_id=jid, jobs_dir=env["jobs"],
                      changes_file=env["changes"], engine_run=fake,
                      lock_path=env["jobs"] / "lock", redirect=False,
                      now_fn=lambda: NOW, **kw)


def test_job_lifecycle(env):
    h, jid = start(env)
    d = job(env, jid)["data"]
    assert d["state"] == "starting" and "client" not in d and d["log_tail"] == []
    fake = FakeEngine(FINDINGS)
    assert run_job(env, h, jid, fake, reboot_pending=lambda: False) == 0
    assert fake.calls == [{"dry_run": True, "fresh": True}, {"dry_run": False, "fresh": False}]
    (env["jobs"] / f"{jid}.log").write_text("".join(f"line {i}\n" for i in range(100)))
    d = job(env, jid, active=False)["data"]
    assert d["state"] == "succeeded" and d["exit_code"] == 0 and d["finished"]
    assert d["result"]["installed"] == ["libc6", "openssl"]
    assert d["result"]["reboot_required"] is True and d["result"]["reboot"] is None
    assert d["log_tail"][-1] == "line 99" and len(d["log_tail"]) == ga.LOG_TAIL
    rec = json.loads(env["changes"].read_text().splitlines()[-1])
    assert rec["kind"] == "apply.finish" and rec["client"] == "203.0.113.5"


def test_job_plan_changed_installs_nothing(env):
    h, jid = start(env)
    fake = FakeEngine([finding("openssl", to="9")])
    assert run_job(env, h, jid, fake) == ga.EXIT_PLAN_CHANGED
    assert [c["dry_run"] for c in fake.calls] == [True]
    d = job(env, jid, active=False)["data"]
    assert d["state"] == "failed" and "plan changed" in d["error"]


def test_job_install_failure(env):
    h, jid = start(env)
    assert run_job(env, h, jid, FakeEngine(FINDINGS, fail=True),
                   reboot_pending=lambda: False) == 1
    d = job(env, jid, active=False)["data"]
    assert d["state"] == "failed" and d["result"]["failed"][0]["error"] == "E: boom"


def test_job_lock_conflict(env):
    import fcntl

    h, jid = start(env)
    env["jobs"].mkdir(exist_ok=True)
    with open(env["jobs"] / "lock", "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        assert run_job(env, h, jid, FakeEngine(FINDINGS)) == ga.EXIT_BUSY
    assert job(env, jid, active=False)["data"]["state"] == "failed"


def test_job_schedules_reboot(env, monkeypatch):
    monkeypatch.setattr(scheduler, "scheduled_reboot", lambda *a, **k: {"state": "none"})
    h, jid = start(env, mode="if_required", at="2026-11-22T18:00Z")
    calls = []

    def runner(argv, timeout=0, **_k):
        calls.append(argv)
        return Cmd(rc=0, out="", err="")

    assert run_job(env, h, jid, FakeEngine(FINDINGS), runner=runner,
                   reboot_at="2026-11-22T18:00:00+00:00", reboot_pending=lambda: False) == 0
    assert calls == [["shutdown", "-r", "+1020", f"kevward (ssh-gate job {jid})"]]
    d = job(env, jid, active=False)["data"]
    assert d["result"]["reboot"]["scheduled"]["at"] == "2026-11-22T18:00:00+00:00"


def test_job_reboot_window_passed_reboots_soon(env, monkeypatch):
    monkeypatch.setattr(scheduler, "scheduled_reboot", lambda *a, **k: {"state": "none"})
    h, jid = start(env)
    calls = []
    run_job(env, h, jid, FakeEngine(FINDINGS), reboot_at="2026-11-22T00:00:00+00:00",
            runner=lambda argv, **k: calls.append(argv) or Cmd(0, "", ""),
            reboot_pending=lambda: True)
    assert calls[0][:3] == ["shutdown", "-r", "+1"]


def test_job_died(env):
    _h, jid = start(env)
    d = job(env, jid, active=False)["data"]
    assert d["state"] == "failed" and "without recording" in d["error"]


@pytest.mark.parametrize("args,code", [
    ({"job_id": "20261122T000000Z-000000"}, "not_found"),
    ({"job_id": "../../etc/passwd"}, "bad_request"),
    ({}, "bad_request"),
])
def test_job_get_errors(env, args, code):
    assert call(env, {"op": "job.get", "args": args}, role="read")["code"] == code


def test_prune_keeps_running(env):
    jobs = env["jobs"]
    ids = [f"202611{d:02d}T000000Z-00000{d % 10}" for d in range(1, 26)]
    for i, jid in enumerate(ids):
        ga.write_job(jobs, {"job_id": jid, "state": "running" if i == 0 else "succeeded"})
    ga.prune_jobs(jobs, keep=5)
    left = sorted(p.stem for p in jobs.glob("*.json"))
    assert left == [ids[0], *ids[-5:]]


# --- CLI and report --------------------------------------------------------------

def test_cli_refuses_minor_with_expect_plan(capsys):
    from kevward import cli
    assert cli.main(["apply", "--yes", "--minor", "--expect-plan", "a" * 64]) == 2
    assert cli.main(["apply", "--expect-plan", "a" * 64]) == 2


def test_findings_for_apply_records():
    recs = [
        {"kind": "apply.start", "time": "t1", "client": "c", "job_id": "J1", "packages": ["a"]},
        {"kind": "apply.start", "time": "t2", "client": "c", "job_id": "J2", "packages": []},
        {"kind": "apply.finish", "time": "t3", "client": "c", "job_id": "J1",
         "state": "succeeded", "result": {"installed": ["a"]}},
    ]
    f = engine.gate_change_findings(recs)
    assert [x.title for x in f] == [
        "apply job J2 started via ssh-gate at t2 from c",
        "packages applied via ssh-gate (job J1) at t3 from c",
    ]
    assert f[1].detail.startswith("Installed: a.")
