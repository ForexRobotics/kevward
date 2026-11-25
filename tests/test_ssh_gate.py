# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#185: kevward ssh-gate, without root, in a temp config dir."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from kevward import audit, cli, engine
from kevward import ssh_gate as g
from kevward.config import Config, tomllib

NOW = datetime(2026, 11, 22, 1, 0, 0, tzinfo=timezone.utc)
BASE = """[audit]
allowed_forced_commands = ["cat /var/log/kevward/report.html"]
allowed_outbound = ["tor:9001"]

[ssh_gate]
enabled = true
"""


@pytest.fixture
def env(tmp_path):
    cfgdir = tmp_path / "etc"
    cfgdir.mkdir()
    path = cfgdir / "config.toml"
    rep = tmp_path / "log"
    rep.mkdir()
    path.write_text(f'report_dir = "{rep}"\n' + BASE)
    (rep / "report.html").write_text("<html>r</html>")
    (rep / "last-run.json").write_text('{"ok": true}')
    return path, tmp_path / "changes.jsonl"


def call(env, req, role="read", raw=None):
    path, changes = env
    body = raw if raw is not None else json.dumps(req).encode()
    resp = g.handle(body, role, path=path, changes_file=changes, client="203.0.113.5", now=NOW)
    line = g.dumps(resp)
    assert line.endswith("\n") and "\n" not in line[:-1]
    keys = set(json.loads(line))
    assert keys in ({"ok", "data"}, {"ok", "error", "code"})  # the stille-pro envelope
    return resp


def sha(path):
    return g._sha(path.read_bytes())


def test_disabled_by_default(env, tmp_path):
    path, _ = env
    path.write_text("[report]\nlang = \"ja\"\n")
    r = call(env, {"op": "version"})
    assert r == {"ok": False, "code": "forbidden",
                 "error": r["error"]} and "disabled" in r["error"]
    missing = tmp_path / "none.toml"
    assert g.handle(b'{"op":"version"}', "read", path=missing)["code"] == "forbidden"


def test_read_ops(env):
    path, _ = env
    v = call(env, {"op": "version"})["data"]
    assert v["protocol"] == 1 and "config.set" not in v["ops"]
    h = call(env, {"op": "report.get", "args": {"format": "html"}})["data"]
    assert h["content"] == "<html>r</html>" and len(h["sha256"]) == 64
    j = call(env, {"op": "report.get", "args": {"format": "json"}})["data"]
    assert j["content"] == {"ok": True}
    assert call(env, {"op": "report.get", "args": {"format": "pdf"}})["code"] == "bad_request"
    c = call(env, {"op": "config.get"})["data"]
    assert c["sha256"] == sha(path) and c["effective"]["audit"]["allowed_outbound"] == ["tor:9001"]
    assert c["warnings"] == [] and c["load_error"] is None
    keys = {k["key"]: k for k in call(env, {"op": "config.schema"})["data"]["keys"]}
    assert keys["report.lang"]["writable"] is True
    assert keys["audit.allowed_outbound"]["writable"] is False
    assert "weaken" in keys["audit.allowed_outbound"]["readonly_reason"]
    assert "path" in keys["report_dir"]["readonly_reason"]
    assert keys["ssh_gate.enabled"]["writable"] is False
    assert "Expected outbound connections" in keys["audit.allowed_outbound"]["help"]


def test_not_found_and_bad_requests(env):
    path, _ = env
    rd = Config.load(path).report_dir
    (rd / "report.html").unlink()
    assert call(env, {"op": "report.get"})["code"] == "not_found"
    assert call(env, None, raw=b"{nope")["code"] == "bad_request"
    assert call(env, None, raw=b"x" * (g.MAX_REQUEST + 1))["code"] == "too_large"
    assert call(env, {"op": "rm -rf"})["code"] == "unknown_op"
    assert call(env, {"op": "version", "args": []})["code"] == "bad_request"
    assert call(env, {"args": {}})["code"] == "bad_request"


def test_config_set_happy_path(env):
    path, changes = env
    before = path.read_text()
    r = call(env, {"op": "config.set", "args": {"set": {"report.lang": "ja"},
                                               "expect_sha256": sha(path)}}, role="operate")
    assert r["ok"], r
    d = r["data"]
    assert d["changes"] == {"report.lang": {"old": "en", "new": "ja"}}
    cfg = Config.load(path)
    assert cfg.report.lang == "ja" and cfg.warnings == []
    assert cfg.audit.allowed_outbound == ["tor:9001"]  # untouched
    assert cfg.ssh_gate.enabled is True
    bak = path.with_name(path.name + ".bak-20261122T010000Z")
    assert bak.read_text() == before and d["backup"] == str(bak)
    rec = json.loads(changes.read_text().splitlines()[0])
    assert rec["client"] == "203.0.113.5" and rec["changes"]["report.lang"]["new"] == "ja"
    # Shown in the report for 7 days, not after.
    recs = g.recent_changes(changes, now=NOW.timestamp() + 3600)
    [f] = engine.gate_change_findings(recs)
    assert "203.0.113.5" in f.title and "'en' → 'ja'" in f.detail
    assert g.recent_changes(changes, now=NOW.timestamp() + 8 * 86400) == []


def test_config_set_refusals(env):
    path, _ = env
    h = sha(path)
    def s(sets, role="operate", expect=h):
        return call(env, {"op": "config.set", "args": {"set": sets, "expect_sha256": expect}},
                    role=role)
    assert s({"report.lang": "ja"}, role="read")["code"] == "forbidden"
    for key in ("audit.allowed_outbound", "audit.allowed_forced_commands", "firewall.allow",
                "update.check", "ssh_gate.enabled", "report_dir", "policy.allow_reboot",
                "no.such"):
        assert s({key: ["198.51.100.1:443"]})["code"] == "forbidden", key
    assert s({"report.lang": "ja"}, expect="0" * 64)["code"] == "conflict"
    assert s({"report.lang": "fr"})["code"] == "bad_request"          # loader rejects
    assert s({"trends.fetch_workers": 99})["code"] == "bad_request"   # would be clamped
    assert s({"trends.fetch_workers": "4"})["code"] == "bad_request"  # wrong type
    assert s({"trends.version_budget_s": float("nan")})["code"] == "bad_request"
    assert s({})["code"] == "bad_request"
    assert sha(path) == h and not list(path.parent.glob("*.bak-*"))   # nothing written


def test_config_set_refuses_when_current_has_ignored_settings(env):
    path, _ = env
    path.write_text(path.read_text() + '\n[report]\nallowed_outbound = ["x:1"]\n')
    r = call(env, {"op": "config.set", "args": {"set": {"report.lang": "ja"},
                                               "expect_sha256": sha(path)}}, role="operate")
    assert r["code"] == "bad_request" and "did you mean [audit]" in r["error"]


def test_backups_pruned(env):
    path, _ = env
    for i in range(12):
        g._prune_backups(path)
        path.with_name(f"{path.name}.bak-2026112{i:02d}").write_text("x")
    g._prune_backups(path)
    assert len(list(path.parent.glob("*.bak-*"))) == g.KEEP_BACKUPS


def test_toml_roundtrip():
    data = {"report_dir": "/var/log/kevward",
            "audit": {"allowed_outbound": ["tor:9001", 'a"b']},
            "policy": {"apply_minor": False, "overrides": {"nginx": {"apply_minor": True}}},
            "trends": {"version_budget_s": 45.0, "fetch_workers": 4},
            "report": {"lang": "ja"}}
    assert tomllib.loads(g.to_toml(data)) == data


def test_audit_recognises_own_gate(tmp_path):
    ak = tmp_path / "authorized_keys"
    ak.write_text(
        'command="/opt/kevward/bin/kevward ssh-gate --role read",restrict ssh-ed25519 AAA r\n'
        'command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate",restrict '
        'ssh-ed25519 AAA o\n')
    ak.chmod(0o600)
    assert audit._check_authkeys([], paths=[str(ak)]) == []
    ak.write_text('command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate; sh",'
                  'restrict ssh-ed25519 AAA o\n')
    assert audit._check_authkeys([], paths=[str(ak)])


def test_cli_entrypoint(env, monkeypatch, capsys):
    path, _ = env
    import io

    class Stdin:
        buffer = io.BytesIO(b'{"op":"version"}')

    monkeypatch.setattr(g.sys, "stdin", Stdin)
    monkeypatch.setattr(g, "_log", lambda *a, **k: None)
    rc = cli.main(["ssh-gate", "--role", "read", "-c", str(path)])
    out = capsys.readouterr().out
    assert rc == 0 and json.loads(out)["data"]["role"] == "read"


# --- #223: key name --------------------------------------------------------------------

def test_stamp_adds_key_name(monkeypatch):
    from kevward import ssh_gate as sg
    monkeypatch.setattr(sg, "_KEY", "console-operate")
    assert sg.stamp({"client": "203.0.113.5"})["key"] == "console-operate"
    monkeypatch.setattr(sg, "_KEY", None)
    assert "key" not in sg.stamp({"client": "203.0.113.5"})


def test_key_name_pattern():
    from kevward import ssh_gate as sg
    assert sg.KEY_NAME.match("console-operate")
    assert not sg.KEY_NAME.match("Console Operate") and not sg.KEY_NAME.match("x" * 41)


def test_change_finding_names_the_key():
    from kevward.engine import gate_change_findings
    f = gate_change_findings([{"time": "t", "client": "203.0.113.5", "key": "console-operate",
                               "kind": "reboot.cancel", "was": {}}])
    assert "(key console-operate) from 203.0.113.5" in f[0].title
    f = gate_change_findings([{"time": "t", "client": "203.0.113.5", "changes": {}}])
    assert "key" not in f[0].title and "from 203.0.113.5" in f[0].title
