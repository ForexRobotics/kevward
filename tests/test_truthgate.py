# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#219: gate.capabilities and the truthgate.* relay."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

import pytest

from kevward import ssh_gate as g
from kevward import truthgate as tg
from kevward.util import BytesCmd, run_bytes

NOW = datetime(2026, 11, 25, 1, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[ssh_gate]\nenabled = true\n')
    return path, tmp_path / "changes.jsonl"


class FakeRunner:
    def __init__(self, out=b'{"ok":true,"data":{"x":1}}\n', timed_out=False):
        self.out, self.timed_out, self.calls = out, timed_out, []

    def __call__(self, argv, input_, timeout, env, kill_grace=5.0):
        self.calls.append((argv, input_, timeout, env))
        return BytesCmd(124 if self.timed_out else 0, b"" if self.timed_out else self.out,
                        timed_out=self.timed_out)


def call(env, raw, role="read", runner=None, check=lambda p: "/usr/bin/truthgate"):
    path, changes = env
    if isinstance(raw, dict):
        raw = json.dumps(raw).encode()
    resp = g.handle(raw, role, path=path, changes_file=changes, client="203.0.113.5",
                    now=NOW, op_opts={"tg_runner": runner, "tg_check": check})
    line = g.dumps(resp)
    assert line.endswith("\n") and "\n" not in line[:-1]
    return resp, line


# --- relay ---------------------------------------------------------------------------

def test_relay_passes_bytes_and_role(env, monkeypatch):
    monkeypatch.setattr(g, "_KEY", "console-operate")
    run = FakeRunner(b'{"ok":false,"error":"no","code":"forbidden"}\n')
    raw = b'{"op":"truthgate.policy.set","args":{"x":"a;b $(id)"}}'
    resp, line = call(env, raw, role="read", runner=run)
    assert line == '{"ok":false,"error":"no","code":"forbidden"}\n'   # unchanged
    argv, input_, timeout, e = run.calls[0]
    assert argv == ["/usr/bin/truthgate", "ssh-gate", "--role", "read"]
    assert input_ == raw and timeout == 120
    assert e == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                 "TRUTHGATE_GATE_CLIENT": "203.0.113.5", "TRUTHGATE_GATE_ROLE": "read",
                 "TRUTHGATE_GATE_KEY_ID": "console-operate"}
    call(env, raw, role="operate", runner=run)
    assert run.calls[1][0][-1] == "operate"


def test_relay_ok_bytes_out(env):
    out = '{"ok":true,"data":{"mode":"enforce","名前":"x"}}\n'.encode()
    resp, line = call(env, {"op": "truthgate.status"}, runner=FakeRunner(out))
    assert line.encode() == out and resp["data"]["mode"] == "enforce"


@pytest.mark.parametrize("out", [b"", b"not json\n", b'{"ok":true}\n{"ok":true}\n',
                                 b'{"ok":"yes"}\n', b"[1]\n", b"\xff\n",
                                 b'{"ok":true,"data":"' + b"a" * tg.MAX_RESPONSE + b'"}\n'])
def test_relay_bad_response(env, out):
    resp, _ = call(env, {"op": "truthgate.status"}, runner=FakeRunner(out))
    assert resp["code"] == "internal" and "bad response" in resp["error"]


def test_relay_timeout(env):
    resp, _ = call(env, {"op": "truthgate.status"}, runner=FakeRunner(timed_out=True))
    assert resp["code"] == "timeout"


def test_relay_not_installed(env, tmp_path):
    p, _ = env
    p.write_text(f'[ssh_gate]\nenabled = true\ntruthgate_path = "{tmp_path}/nope"\n')
    resp, _ = call(env, {"op": "truthgate.status"}, runner=FakeRunner(), check=None)
    assert resp["code"] == "not_installed"


def test_relay_disabled(env):
    p, _ = env
    p.write_text("[ssh_gate]\nenabled = false\n")
    run = FakeRunner()
    resp, _ = call(env, {"op": "truthgate.status"}, runner=run)
    assert resp["code"] == "forbidden" and not run.calls


def test_relay_not_logged(env, monkeypatch):
    msgs = []
    import syslog
    monkeypatch.setattr(syslog, "syslog", lambda *a: msgs.append(a[-1]))
    raw = b'{"op":"truthgate.policy.set","args":{"secret":"s3cret"}}'
    resp, _ = call(env, raw, runner=FakeRunner(b'{"ok":true,"data":{"changes":{"a":1}}}\n'))
    g._log("read", raw, resp, "203.0.113.5")
    assert "op=truthgate.policy.set ok" in msgs[0]
    assert "s3cret" not in msgs[0] and "changes" not in msgs[0]


# --- path safety ---------------------------------------------------------------------

def _exe(d, mode=0o755):
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    f = d / "truthgate"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, mode)
    return f


def test_checked_path(tmp_path, monkeypatch):
    uid = os.getuid()
    monkeypatch.setattr(tg, "_safe", _safe_below(tmp_path, tg._safe))
    f = _exe(tmp_path / "bin")
    assert tg.checked_path(str(f), owner=uid) == str(f)
    os.chmod(f, 0o775)
    with pytest.raises(g.GateError) as ei:
        tg.checked_path(str(f), owner=uid)
    assert ei.value.code == "forbidden"
    os.chmod(f, 0o755)
    os.chmod(tmp_path / "bin", 0o777)
    with pytest.raises(g.GateError):
        tg.checked_path(str(f), owner=uid)
    os.chmod(tmp_path / "bin", 0o755)
    with pytest.raises(g.GateError) as ei:
        tg.checked_path(str(f), owner=uid + 1)            # not owned by "root"
    assert ei.value.code == "forbidden"
    with pytest.raises(g.GateError) as ei:
        tg.checked_path("bin/truthgate", owner=uid)
    assert ei.value.code == "forbidden"


def test_checked_path_symlink_to_unsafe(tmp_path, monkeypatch):
    uid = os.getuid()
    monkeypatch.setattr(tg, "_safe", _safe_below(tmp_path, tg._safe))
    bad = _exe(tmp_path / "w")
    os.chmod(tmp_path / "w", 0o777)
    (tmp_path / "bin").mkdir(mode=0o755)
    link = tmp_path / "bin" / "truthgate"
    link.symlink_to(bad)
    with pytest.raises(g.GateError) as ei:
        tg.checked_path(str(link), owner=uid)
    assert ei.value.code == "forbidden"
    (tmp_path / "d").mkdir(mode=0o755)
    with pytest.raises(g.GateError) as ei:
        tg.checked_path(str(tmp_path / "d"), owner=uid)   # not a regular file
    assert ei.value.code == "forbidden"


def _safe_below(top, real):
    """Apply the real check only at and below ``top`` (pytest's tmp dirs sit
    under /tmp, which is world-writable by design)."""
    top = str(top)

    def check(st, what, owner):
        name = what.removeprefix("directory ")
        if name == top or name.startswith(top + "/"):
            real(st, what, owner)
    return check


# --- run_bytes (real processes) ------------------------------------------------------

def test_run_bytes_env_stdin_stderr(tmp_path):
    script = ("import json,os,sys; d=sys.stdin.buffer.read(); sys.stderr.write('noise');"
              "print(json.dumps({'env': sorted(os.environ), 'in': d.decode()}))")
    r = run_bytes([sys.executable, "-c", script], b"hello", 10, {"A": "1"})
    assert r.rc == 0 and not r.timed_out and b"noise" not in r.out
    got = json.loads(r.out)
    assert got["in"] == "hello" and set(got["env"]) - {"LC_CTYPE"} == {"A"}


def test_run_bytes_timeout_kills_group():
    t0 = time.monotonic()
    script = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    r = run_bytes([sys.executable, "-c", script], b"", 0.5, {}, kill_grace=0.5)
    assert r.timed_out and r.rc == 124 and time.monotonic() - t0 < 10


# --- gate.capabilities ---------------------------------------------------------------

def test_capabilities_without_truthgate(env, tmp_path):
    p, _ = env
    p.write_text(f'[ssh_gate]\nenabled = true\ntruthgate_path = "{tmp_path}/nope"\n')
    resp, _ = call(env, {"op": "gate.capabilities"}, check=None)
    d = resp["data"]
    assert d["protocol"] == 1 and d["role"] == "read" and d["gate_user"]
    assert set(d["products"]) == {"kevward"}
    assert "gate.capabilities" in d["products"]["kevward"]["ops"]
    assert "config.set" not in d["products"]["kevward"]["ops"]


def test_capabilities_with_truthgate(env):
    run = FakeRunner(b'{"ok":true,"data":{"version":"0.1.0","protocol":1}}\n')
    resp, _ = call(env, {"op": "gate.capabilities"}, role="operate", runner=run)
    d = resp["data"]
    assert d["products"]["truthgate"] == {"version": "0.1.0", "protocol": 1}
    assert "config.set" in d["products"]["kevward"]["ops"]
    assert run.calls[0][1] == b'{"op":"truthgate.capabilities"}' and run.calls[0][2] == 5


@pytest.mark.parametrize("run", [FakeRunner(timed_out=True), FakeRunner(b"junk\n"),
                                 FakeRunner(b'{"ok":false,"error":"x","code":"unavailable"}\n')])
def test_capabilities_broken_truthgate_omitted(env, run):
    resp, _ = call(env, {"op": "gate.capabilities"}, runner=run)
    assert resp["ok"] and set(resp["data"]["products"]) == {"kevward"}


def test_truthgate_path_read_only():
    s = g.schema()
    keys = {k["key"]: k for k in s["keys"]} if isinstance(s["keys"], list) else s["keys"]
    k = keys["ssh_gate.truthgate_path"]
    assert not k.get("writable")
