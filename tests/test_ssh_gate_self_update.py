# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#190: ssh-gate self.update, with a fake pip runner (no network, no root)."""

from __future__ import annotations

import fcntl
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kevward import __version__, engine
from kevward import ssh_gate as g
from kevward.config import Config
from kevward.util import Cmd

NOW = datetime(2026, 11, 22, 5, 0, 0, tzinfo=timezone.utc)
VENV = Path(sys.prefix)          # the test venv stands in for /opt/kevward
IN_VENV = sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def cfg(self_update=True, min_version=""):
    return Config.from_dict({"ssh_gate": {"enabled": True, "self_update": self_update,
                                          "min_version": min_version}})


PIP_OK = Cmd(0, "Successfully installed kevward-9.9.9\n", "")


class FakeRunner:
    def __init__(self, pip=PIP_OK, version=None):
        self.pip, self.version, self.calls = pip, version, []

    def __call__(self, args, timeout=120, env=None, clean_env=False):
        self.calls.append((args, timeout, env, clean_env))
        if args[1:3] == ["-m", "pip"]:
            return self.pip
        want = args and self.calls[0][0][-1].split("==")[1]
        return self.version or Cmd(0, f"kevward {want}\n", "")


def run(tmp_path, args, c=None, runner=None, prefix=VENV):
    runner = runner or FakeRunner()
    data = g.op_self_update(c or cfg(), args, changes_file=tmp_path / "ch.jsonl",
                            client="203.0.113.5", now=NOW, runner=runner, prefix=prefix,
                            lock_path=tmp_path / "lock")
    return data, runner


needs_venv = pytest.mark.skipif(not IN_VENV, reason="tests run outside a venv")


@needs_venv
def test_update_happy_path_and_record(tmp_path):
    data, r = run(tmp_path, {"version": "99.0.0"})
    assert data["old"] == __version__ and data["new"] == "99.0.0"
    assert data["downgrade"] is False and "Successfully installed" in data["pip_tail"]
    args, timeout, env, clean = r.calls[0]
    assert args[0] == str(VENV / "bin" / "python")
    assert args[-1] == "kevward==99.0.0" and "--isolated" in args
    assert "--index-url" in args and "https://pypi.org/simple" in args
    assert timeout == g.UPDATE_TIMEOUT_S and clean is True
    assert env["PIP_CONFIG_FILE"] == "/dev/null" and not any(
        k.startswith("PIP_") and k != "PIP_CONFIG_FILE" for k in env)
    assert r.calls[1][0] == [str(VENV / "bin" / "kevward"), "--version"]
    rec = json.loads((tmp_path / "ch.jsonl").read_text())
    assert rec["kind"] == "self.update" and rec["new"] == "99.0.0"
    [f] = engine.gate_change_findings([rec])
    assert f"kevward updated {__version__} → 99.0.0 via ssh-gate" in f.title
    assert "203.0.113.5" in f.title


@needs_venv
def test_downgrade_flag_and_floor(tmp_path):
    c = cfg(min_version="0.17.0")
    data, _ = run(tmp_path, {"version": "0.17.0"}, c=c)
    assert data["downgrade"] is (g._vtuple("0.17.0") < g._vtuple(__version__))
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "0.16.0"}, c=c)
    assert e.value.code == "forbidden" and "minimum 0.17.0" in e.value.message
    with pytest.raises(g.GateError) as e:   # default floor: the first release with the op
        run(tmp_path, {"version": "0.15.0"})
    assert e.value.code == "forbidden"


@pytest.mark.parametrize("v", ["latest", "1.0", "1.0.0rc1", "1.0.0 ; rm", "", None, 1,
                               "../1.0.0", "1.0.0\n"])
def test_bad_versions(tmp_path, v):
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": v})
    assert e.value.code == "bad_request"


def test_opt_in_and_venv_required(tmp_path):
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"}, c=cfg(self_update=False))
    assert e.value.code == "forbidden" and "self_update" in e.value.message
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"}, prefix=tmp_path / "opt-kevward")
    assert e.value.code == "forbidden" and "not a venv install" in e.value.message


@needs_venv
def test_pip_failures_and_version_check(tmp_path):
    nf = Cmd(1, "", "ERROR: No matching distribution found for kevward==99.0.0\n")
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"}, runner=FakeRunner(pip=nf))
    assert e.value.code == "not_found"
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"}, runner=FakeRunner(pip=Cmd(1, "", "boom\n")))
    assert e.value.code == "internal" and "boom" in e.value.message
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"}, runner=FakeRunner(pip=Cmd(124, "", "")))
    assert e.value.code == "internal" and "timed out" in e.value.message
    with pytest.raises(g.GateError) as e:
        run(tmp_path, {"version": "99.0.0"},
            runner=FakeRunner(version=Cmd(0, "kevward 0.16.0\n", "")))
    assert e.value.code == "internal" and "not 99.0.0" in e.value.message
    assert not (tmp_path / "ch.jsonl").exists()


@needs_venv
def test_lock_conflict_and_unchanged(tmp_path):
    with open(tmp_path / "lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(g.GateError) as e:
            run(tmp_path, {"version": "99.0.0"})
        assert e.value.code == "conflict"
    data, r = run(tmp_path, {"version": __version__}, c=cfg(min_version="0.1.0"))
    assert data["unchanged"] is True and r.calls == []


def test_through_handle_roles_and_version_op(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[ssh_gate]\nenabled = true\n")
    req = json.dumps({"op": "self.update", "args": {"version": "99.0.0"}}).encode()
    r = g.handle(req, "read", path=p, changes_file=tmp_path / "c")
    assert r["code"] == "forbidden" and "operate" in r["error"]
    r = g.handle(req, "operate", path=p, changes_file=tmp_path / "c")
    assert r["code"] == "forbidden" and "self_update" in r["error"]
    v = g.handle(b'{"op":"version"}', "operate", path=p)["data"]
    assert "self.update" in v["ops"] and v["self_update"] is False
    assert v["min_version"] == g.SELF_UPDATE_SINCE and v["install"]["method"] in ("venv",
                                                                                  "other")


def test_config_validation(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[ssh_gate]\nmin_version = "latest"\n')
    assert Config.load(p).load_error
    p.write_text('[ssh_gate]\nself_update = "yes"\n')
    assert Config.load(p).load_error
    p.write_text('[ssh_gate]\nself_update = true\nmin_version = "0.17.0"\n')
    c = Config.load(p)
    assert c.load_error is None and c.ssh_gate.self_update is True
