# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#237: the report says when the console cannot get in; #235: setup --refresh."""

from __future__ import annotations

from kevward import engine
from kevward import schedule as sch
from kevward import setup as su

READ = 'command="/opt/kevward/bin/kevward ssh-gate --role read",restrict ssh-rsa AAAA a\n'
OPER = ('command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate",restrict '
        'ssh-rsa BBBB b\n')


def _home(tmp_path, name, text):
    h = tmp_path / name
    (h / ".ssh").mkdir(parents=True)
    (h / ".ssh" / "authorized_keys").write_text(text)
    return str(h)


def test_gate_access_counts_roles(tmp_path):
    sudoers = tmp_path / "sudoers"
    homes = [_home(tmp_path, "a", "ssh-ed25519 X me\n" + READ),
             _home(tmp_path, "b", OPER), str(tmp_path / "missing")]
    assert engine.gate_access(homes, str(sudoers)) == {"read": 1, "operate": 1,
                                                       "sudoers": False, "checked": 2}


def test_findings():
    none = {"read": 0, "operate": 0, "sudoers": False}
    f = engine.gate_access_findings(True, none, snapshot_exists=True)
    assert f[0].severity.value == "medium" and "no authorized_keys entry" in f[0].title
    assert "setup --restore" in f[0].detail
    assert "--read-key" in engine.gate_access_findings(True, none, False)[0].detail
    f = engine.gate_access_findings(True, {"read": 1, "operate": 1, "sudoers": False}, False)
    assert "without /etc/sudoers.d/kevward-ssh-gate" in f[0].title
    assert engine.gate_access_findings(True, {"read": 1, "operate": 1, "sudoers": True},
                                       False) == []
    assert engine.gate_access_findings(True, {"read": 1, "operate": 0, "sudoers": False},
                                       False) == []
    assert engine.gate_access_findings(False, none, False) == []


def test_setup_refresh_step(tmp_path, monkeypatch):
    env = su.Env(etc=tmp_path / "etc", unit_dir=tmp_path / "units",
                 changes_file=tmp_path / "c.jsonl", is_root=lambda: True)
    (tmp_path / "units").mkdir()
    (tmp_path / "units" / sch.SERVICE).write_text("[Service]\n")
    monkeypatch.setattr(sch, "is_root", lambda: True)
    monkeypatch.setattr(sch, "have", lambda c: False)
    d = su.setup(refresh=True, env=env)
    (a,) = d["actions"]
    assert a["kind"] == "refresh" and a["action"] == "update" and d["changed"]
    assert (tmp_path / "units" / f"{sch.SERVICE}.d" / sch.SERVICE_DROPIN_NAME).exists()
    assert su.setup(refresh=True, env=env)["actions"][0]["action"] == "unchanged"
