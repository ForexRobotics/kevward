# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#291: client.exempt / client.exempt_clear, one fail2ban slot per console key."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import exempt as ex
from kevward import ssh_gate as g
from kevward.engine import gate_change_findings
from kevward.model import Severity
from kevward.util import Cmd

NOW = datetime(2026, 11, 29, 0, 0, tzinfo=timezone.utc)
OFFICE_OLD, OFFICE_NEW = "106.73.233.64", "106.73.240.12"
BASE = ["127.0.0.1/8", "::1", "124.44.207.82"]


class FakeF2B:
    """fail2ban-client: -t, reload, get sshd ignoreip, driven by the slot file."""

    def __init__(self, f2b_dir, base=BASE, fail=None, drop=False):
        self.dir, self.base, self.fail, self.drop, self.calls = f2b_dir, list(base), fail, \
            drop, []

    def _effective(self):
        conf = self.dir / "jail.d" / ex.SLOT_CONF_NAME
        extra = []
        if conf.exists():
            for ln in conf.read_text().splitlines():
                if ln.startswith("ignoreip"):
                    extra = [t for t in ln.split("=", 1)[1].split() if "%(" not in t]
        base = [] if self.drop else self.base
        return base + [t for t in extra if t not in base]

    def __call__(self, argv, timeout=60, **kw):
        self.calls.append(argv[1:])
        if argv[1:] == ["-t"]:
            return Cmd(1, "", "ERROR bad") if self.fail == "test" else Cmd(0, "OK", "")
        if argv[1:] == ["reload"]:
            return Cmd(1, "", "boom") if self.fail == "reload" else Cmd(0, "OK", "")
        if argv[1:] == ["get", "sshd", "ignoreip"]:
            if self.fail == "get":
                return Cmd(255, "", "Sorry but the jail 'sshd' does not exist")
            lines = "\n".join(f"|- {t}" if i < len(self._effective()) - 1 else f"`- {t}"
                              for i, t in enumerate(self._effective()))
            return Cmd(0, "These IP addresses/networks are ignored:\n" + lines, "")
        raise AssertionError(argv)


@pytest.fixture
def env(tmp_path):
    (tmp_path / "fail2ban" / "jail.d").mkdir(parents=True)
    return {"f2b_dir": tmp_path / "fail2ban", "slots_file": tmp_path / "lib" / "slots.json",
            "changes_file": tmp_path / "changes.jsonl"}


def call(env, fn, client, key="console-operate", runner=None):
    return fn(client=client, key=key, now=NOW, runner=runner or FakeF2B(env["f2b_dir"]),
              **env)


def changes(env):
    return [json.loads(ln) for ln in env["changes_file"].read_text().splitlines()]


def test_first_exempt(env):
    f = FakeF2B(env["f2b_dir"])
    r = call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    assert r == {"address": OFFICE_OLD, "replaced": None, "key": "console-operate",
                 "fail2ban_ignored": True}
    text = (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).read_text()
    assert "[sshd]\nignoreip = %(known/ignoreip)s 106.73.233.64\n" in text
    assert ex.slot_of("console-operate", env["slots_file"]) == OFFICE_OLD
    assert ["-t"] in f.calls and ["reload"] in f.calls
    assert changes(env)[-1]["kind"] == "client.exempt"


def test_replace_keeps_manual_entries(env):
    f = FakeF2B(env["f2b_dir"], base=BASE + [OFFICE_OLD])   # also added by hand
    call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    r = call(env, ex.op_exempt, OFFICE_NEW, runner=f)
    assert r["replaced"] == OFFICE_OLD and r["fail2ban_ignored"]
    eff = f._effective()
    assert OFFICE_NEW in eff and OFFICE_OLD in eff          # the hand-added one stays
    text = (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).read_text()
    assert OFFICE_OLD not in text.split("[sshd]")[1]


def test_same_address_is_a_noop(env):
    f = FakeF2B(env["f2b_dir"])
    call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    n = len(changes(env))
    r = call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    assert r["replaced"] is None and r["fail2ban_ignored"] and len(changes(env)) == n


def test_slots_per_key(env):
    f = FakeF2B(env["f2b_dir"])
    call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    call(env, ex.op_exempt, "203.0.113.77", key="laptop-operate", runner=f)
    eff = f._effective()
    assert OFFICE_OLD in eff and "203.0.113.77" in eff


@pytest.mark.parametrize("fail", ["test", "reload"])
def test_failure_rolls_back(env, fail):
    f = FakeF2B(env["f2b_dir"])
    call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    before = (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).read_text()
    f.fail = fail
    with pytest.raises(g.GateError) as ei:
        call(env, ex.op_exempt, OFFICE_NEW, runner=f)
    assert ei.value.code == "internal" and "put back" in ei.value.message
    assert (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).read_text() == before
    assert ex.slot_of("console-operate", env["slots_file"]) == OFFICE_OLD


def test_reload_that_drops_exemptions_rolls_back(env):
    f = FakeF2B(env["f2b_dir"])
    f.drop_after = True

    class Dropping(FakeF2B):
        def _effective(self):
            eff = super()._effective()
            conf = self.dir / "jail.d" / ex.SLOT_CONF_NAME
            return [t for t in eff if t != "124.44.207.82"] if conf.exists() else eff

    d = Dropping(env["f2b_dir"])
    with pytest.raises(g.GateError) as ei:
        call(env, ex.op_exempt, OFFICE_OLD, runner=d)
    assert "dropped exemptions" in ei.value.message
    assert not (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).exists()
    assert ex.slot_of("console-operate", env["slots_file"]) is None


@pytest.mark.parametrize("client,key,why", [
    ("", "console-operate", "address is not known"),
    ("not-an-ip", "console-operate", "address is not known"),
    (OFFICE_OLD, None, "has no name"),
])
def test_preconditions(env, client, key, why):
    with pytest.raises(g.GateError) as ei:
        call(env, ex.op_exempt, client, key=key)
    assert ei.value.code == "precondition_failed" and why in ei.value.message


def test_no_fail2ban(env, tmp_path):
    env["f2b_dir"] = tmp_path / "nope"
    with pytest.raises(g.GateError) as ei:
        call(env, ex.op_exempt, OFFICE_OLD)
    assert ei.value.code == "precondition_failed"


def test_sshd_jail_not_running(env):
    with pytest.raises(g.GateError) as ei:
        call(env, ex.op_exempt, OFFICE_OLD, runner=FakeF2B(env["f2b_dir"], fail="get"))
    assert ei.value.code == "precondition_failed"


def test_clear(env):
    f = FakeF2B(env["f2b_dir"])
    call(env, ex.op_exempt, OFFICE_OLD, runner=f)
    r = call(env, ex.op_exempt_clear, OFFICE_NEW, runner=f)
    assert r == {"cleared": OFFICE_OLD, "key": "console-operate"}
    assert not (env["f2b_dir"] / "jail.d" / ex.SLOT_CONF_NAME).exists()
    assert call(env, ex.op_exempt_clear, OFFICE_NEW, runner=f)["cleared"] is None


def test_ipv6_single_address(env):
    f = FakeF2B(env["f2b_dir"])
    r = call(env, ex.op_exempt, "2001:db8:0:1::5", runner=f)
    assert r["address"] == "2001:db8:0:1::5"


def test_render_none_when_empty():
    assert ex.render({}) is None


def test_gate_dispatch_and_roles(env, tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[ssh_gate]\nenabled = true\n")
    monkeypatch.setattr(g, "_KEY", "console-operate")
    opts = {"runner": FakeF2B(env["f2b_dir"]), "f2b_dir": env["f2b_dir"],
            "slots_file": env["slots_file"]}
    r = g.handle(b'{"op":"client.exempt"}', "read", path=cfg,
                 changes_file=env["changes_file"], client=OFFICE_OLD, op_opts=opts)
    assert r["code"] == "forbidden"
    r = g.handle(b'{"op":"client.exempt","args":{"address":"8.8.8.8"}}', "operate", path=cfg,
                 changes_file=env["changes_file"], client=OFFICE_OLD, op_opts=opts)
    assert r["ok"] and r["data"]["address"] == OFFICE_OLD    # args ignored: caller's own
    assert "client.exempt" in g.OPERATE_OPS and "client.exempt" not in g.READ_OPS


def test_report_finding_low():
    fs = gate_change_findings([{"time": NOW.isoformat(), "client": OFFICE_NEW,
                                "key": "console-operate", "kind": "client.exempt",
                                "address": OFFICE_NEW, "replaced": OFFICE_OLD}])
    assert fs[0].severity == Severity.LOW
    assert f"set to {OFFICE_NEW} (replacing {OFFICE_OLD})" in fs[0].title
    assert "(key console-operate)" in fs[0].title
