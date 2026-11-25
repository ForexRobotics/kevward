# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#191: kevward setup against a temp root (no real /etc, no root needed)."""

from __future__ import annotations

import base64
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kevward import cli, engine
from kevward import setup as su
from kevward.config import Config
from kevward.ssh_gate import GateError
from kevward.util import Cmd

NOW = datetime(2026, 11, 22, 6, 0, 0, tzinfo=timezone.utc)


def key(seed: int, comment: str) -> str:
    t = b"ssh-ed25519"
    blob = struct.pack(">I", len(t)) + t + struct.pack(">I", 32) + bytes([seed]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


READ, OPERATE = key(1, "fr-security-centre-read"), key(2, "fr-security-centre-operate")


class Runner:
    def __init__(self, rc=0):
        self.rc, self.calls = rc, []

    def __call__(self, args, timeout=120, **k):
        self.calls.append(args)
        return Cmd(self.rc, "", "" if self.rc == 0 else "syntax error\n")


@pytest.fixture
def env(tmp_path):
    etc, home, prefix = tmp_path / "etc", tmp_path / "home" / "ktakahashi", tmp_path / "opt"
    (etc / "sudoers.d").mkdir(parents=True)
    (etc / "kevward").mkdir()
    home.mkdir(parents=True)
    os.chmod(home, 0o755)
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin" / "kevward").write_text("#!/bin/sh\n")
    uid, gid = os.getuid(), os.getgid()
    e = su.Env(etc=etc, prefix=prefix, changes_file=tmp_path / "changes.jsonl",
               unit_dir=tmp_path / "units", lookup_user=lambda n: (uid, gid, home),
               runner=Runner(), now=NOW, is_root=lambda: True)
    return e, home


def test_parse_pubkey():
    assert su.parse_pubkey(READ)[2] == "fr-security-centre-read"
    for bad in ["", "ssh-ed25519 AAAA", 'ssh-ed25519 AAAA c "x"', "ssh-dss AAAA c",
                "ssh-ed25519 !!!! c", key(1, "c") + "\nssh-rsa x y",
                key(1, "bad comment with spaces").rsplit(" ", 3)[0] + " a b",
                'command="sh" ' + READ, key(1, "c;rm")]:
        with pytest.raises(GateError):
            su.parse_pubkey(bad)
    # type inside the blob must match the declared type
    with pytest.raises(GateError):
        su.parse_pubkey(READ.replace("ssh-ed25519", "ssh-rsa", 1))


def test_keys_sudoers_idempotent_and_replaces(env):
    e, home = env
    ak = home / ".ssh" / "authorized_keys"
    (home / ".ssh").mkdir(mode=0o700)
    # An existing *unrestricted* line for the same key must be replaced, a
    # personal key kept, and an old gate line with the same comment (rotated
    # console key) dropped.
    old_rotated = su.gate_line("read", key(9, "fr-security-centre-read"), e.prefix)
    ak.write_text(f"ssh-ed25519 AAAApersonal me@pc\n{key(1, 'old-comment')}\n{old_rotated}\n")
    os.chmod(ak, 0o600)
    d = su.setup(console_user="ktakahashi", read_key=READ, operate_key=OPERATE, env=e)
    lines = ak.read_text().splitlines()
    assert lines[0] == "ssh-ed25519 AAAApersonal me@pc"
    assert lines[1] == (f'command="{e.prefix}/bin/kevward ssh-gate --role read '
                        '--key-name console-read",restrict ' + READ)
    assert lines[2] == (f'command="sudo -n {e.prefix}/bin/kevward ssh-gate --role operate '
                        '--key-name console-operate",restrict ' + OPERATE)
    assert len(lines) == 3 and oct(ak.stat().st_mode & 0o777) == "0o600"
    sud = e.etc / "sudoers.d" / su.SUDOERS_NAME
    assert sud.read_text().splitlines()[-2:] == [
        f"ktakahashi ALL=(root) NOPASSWD: {e.prefix}/bin/kevward ssh-gate --role operate "
        "--key-name console-operate",
        f"ktakahashi ALL=(root) NOPASSWD: {e.prefix}/bin/kevward ssh-gate --role operate"]
    assert oct(sud.stat().st_mode & 0o777) == "0o440"
    assert e.runner.calls[0][:2] == ["visudo", "-cf"]
    assert {a["kind"]: a["action"] for a in d["actions"]} == {
        "authorized_keys": "update", "sudoers": "create"}
    # second run: nothing changes, nothing recorded twice
    d2 = su.setup(console_user="ktakahashi", read_key=READ, operate_key=OPERATE, env=e)
    assert d2["changed"] is False and ak.read_text().splitlines() == lines
    assert len(e.changes_file.read_text().splitlines()) == 1


def test_dry_run_writes_nothing(env):
    e, home = env
    d = su.setup(console_user="ktakahashi", read_key=READ, operate_key=OPERATE,
                 ssh_gate=True, fail2ban_ignore=["124.44.207.82"], dry_run=True, env=e)
    kinds = [(a["kind"], a["action"]) for a in d["actions"]]
    assert ("authorized_keys", "create") in kinds and ("sudoers", "create") in kinds
    assert ("config", "create") in kinds and ("fail2ban", "skipped") in kinds
    assert not (home / ".ssh").exists() and not list((e.etc / "sudoers.d").iterdir())
    assert not (e.etc / "kevward" / "config.toml").exists() and not e.changes_file.exists()


def test_refuses_unsafe_files(env):
    e, home = env
    (home / ".ssh").mkdir(mode=0o700)
    target = home / "elsewhere"
    target.write_text("")
    (home / ".ssh" / "authorized_keys").symlink_to(target)
    with pytest.raises(GateError) as x:
        su.setup(console_user="ktakahashi", read_key=READ, env=e)
    assert x.value.code == "forbidden" and "symlink" in x.value.message
    (home / ".ssh" / "authorized_keys").unlink()
    os.chmod(home / ".ssh", 0o777)
    with pytest.raises(GateError) as x:
        su.setup(console_user="ktakahashi", read_key=READ, env=e)
    assert "writable" in x.value.message


def test_visudo_failure_leaves_nothing(env):
    e, _ = env
    e.runner = Runner(rc=1)
    with pytest.raises(GateError) as x:
        su.setup(console_user="ktakahashi", operate_key=OPERATE, env=e)
    assert x.value.code == "internal" and "visudo" in x.value.message
    assert not list((e.etc / "sudoers.d").iterdir())


def test_ssh_gate_config_and_fail2ban(env):
    e, _ = env
    cfgp = e.etc / "kevward" / "config.toml"
    cfgp.write_text('[audit]\nallowed_outbound = ["tor:9001"]\n')
    (e.etc / "fail2ban" / "jail.d").mkdir(parents=True)
    d = su.setup(ssh_gate=True, fail2ban_ignore=["124.44.207.82", "2001:db8::/32"], env=e)
    c = Config.load(cfgp)
    assert c.ssh_gate.enabled is True and c.audit.allowed_outbound == ["tor:9001"]
    assert list(cfgp.parent.glob("config.toml.bak-*"))
    f2b = (e.etc / "fail2ban" / "jail.d" / su.F2B_NAME).read_text()
    assert "ignoreip = 127.0.0.1/8 ::1 124.44.207.82/32 2001:db8::/32\n" in f2b
    assert e.runner.calls[-2:] == [["fail2ban-client", "-t"], ["fail2ban-client", "reload"]]
    assert d["changed"] is True
    again = su.setup(ssh_gate=True, fail2ban_ignore=["124.44.207.82", "2001:db8::/32"], env=e)
    assert again["changed"] is False
    with pytest.raises(GateError):
        su.setup(fail2ban_ignore=["not-an-ip"], env=e)
    cfgp.write_text('[report]\nallowed_outbound = ["x:1"]\n')   # #186: fix first
    with pytest.raises(GateError) as x:
        su.setup(ssh_gate=True, env=e)
    assert "did you mean [audit]" in x.value.message


def test_argument_checks(env):
    e, _ = env
    for kw, code in [({}, "bad_request"), ({"read_key": READ}, "bad_request"),
                     ({"console_user": "Bad User", "read_key": READ}, "bad_request"),
                     ({"console_user": "ktakahashi", "read_key": "nope"}, "bad_request")]:
        with pytest.raises(GateError) as x:
            su.setup(env=e, **kw)
        assert x.value.code == code
    e.is_root = lambda: False
    with pytest.raises(GateError) as x:
        su.setup(ssh_gate=True, env=e)
    assert x.value.code == "forbidden"
    assert su.setup(ssh_gate=True, dry_run=True, env=e)["dry_run"] is True
    e.is_root = lambda: True
    (e.prefix / "bin" / "kevward").unlink()
    with pytest.raises(GateError) as x:
        su.setup(console_user="ktakahashi", read_key=READ, env=e)
    assert x.value.code == "not_found"


def test_report_finding_and_audit_accepts_lines(env):
    e, home = env
    su.setup(console_user="ktakahashi", read_key=READ, operate_key=OPERATE, env=e)
    rec = json.loads(e.changes_file.read_text())
    [f] = engine.gate_change_findings([rec])
    assert f.title.startswith("kevward setup changed 2 item(s)")
    from kevward import audit
    real = su.gate_line("read", READ), su.gate_line("operate", OPERATE)
    p = home / "ak"
    p.write_text("\n".join(real) + "\n")
    os.chmod(p, 0o600)
    assert audit._check_authkeys([], paths=[str(p)]) == []


def test_cli_json_envelope(monkeypatch, capsys):
    monkeypatch.setattr(su, "setup", lambda **k: (_ for _ in ()).throw(
        GateError("forbidden", "kevward setup must run as root (sudo)")))
    rc = cli.main(["setup", "--ssh-gate", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2 and out == {"ok": False, "error": "kevward setup must run as root (sudo)",
                               "code": "forbidden"}
    monkeypatch.setattr(su, "setup", lambda **k: {"dry_run": True, "changed": True,
                                                   "actions": []})
    rc = cli.main(["setup", "--ssh-gate", "--dry-run", "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["ok"] is True


def test_paths_are_absolute():
    assert Path(su.gate_command("read")).is_absolute()
    assert su.gate_command("operate").startswith("sudo -n /opt/kevward/bin/kevward ")


def test_timer_dry_run_lists_units(env):
    e, _ = env
    d = su.setup(timer=True, dry_run=True, env=e)
    paths = {a["path"] for a in d["actions"] if a["kind"] == "timer"}
    assert str(e.unit_dir / "kevward-report.timer") in paths
    assert not e.unit_dir.exists()


# --- fail2ban: [DEFAULT] cannot use %(known/...)s --------------------------------

def test_fail2ban_never_writes_known_interpolation(env):
    e, _ = env
    f2b = e.etc / "fail2ban"
    (f2b / "jail.d").mkdir(parents=True)
    (f2b / "jail.conf").write_text("[DEFAULT]\n#ignoreip = 127.0.0.1/8 ::1\nbantime = 10m\n"
                                   "[sshd]\nenabled = true\n")
    (f2b / "jail.local").write_text("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 192.0.2.0/24,"
                                    " 198.51.100.7 %(known/ignoreip)s\n")
    (f2b / "jail.d" / "defaults-debian.conf").write_text("[sshd]\nenabled = true\n")
    (f2b / "jail.d" / "zz-later.local").write_text("[DEFAULT]\nignoreip = 203.0.113.99\n")
    su.setup(fail2ban_ignore=["124.44.207.82"], env=e)
    text = (f2b / "jail.d" / su.F2B_NAME).read_text()
    body = [ln for ln in text.splitlines() if not ln.startswith("#")]
    assert body == ["[DEFAULT]",
                    "ignoreip = 127.0.0.1/8 ::1 192.0.2.0/24 198.51.100.7 124.44.207.82/32"]


def test_fail2ban_check_failure_restores(env):
    e, _ = env
    jd = e.etc / "fail2ban" / "jail.d"
    jd.mkdir(parents=True)

    class F2bRunner(Runner):
        def __call__(self, args, timeout=120, **k):
            self.calls.append(args)
            bad = args == ["fail2ban-client", "-t"]
            return Cmd(1 if bad else 0, "", "ERROR Failed during configuration\n" if bad else "")

    e.runner = F2bRunner()
    with pytest.raises(GateError) as x:
        su.setup(fail2ban_ignore=["124.44.207.82"], env=e)
    assert x.value.code == "internal" and "removed" in x.value.message
    assert not (jd / su.F2B_NAME).exists()
    assert ["fail2ban-client", "reload"] not in e.runner.calls
    # an existing file is put back as it was
    (jd / su.F2B_NAME).write_text("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 10.0.0.1/32\n")
    with pytest.raises(GateError) as x:
        su.setup(fail2ban_ignore=["124.44.207.82"], env=e)
    assert "restored" in x.value.message
    assert "10.0.0.1/32" in (jd / su.F2B_NAME).read_text()


def test_failure_keeps_keys_untouched_and_reports_progress(env):
    e, home = env
    (e.etc / "fail2ban" / "jail.d").mkdir(parents=True)
    e.runner = Runner(rc=1)  # fail2ban-client -t fails
    with pytest.raises(GateError) as x:
        su.setup(console_user="ktakahashi", read_key=READ, ssh_gate=True,
                 fail2ban_ignore=["124.44.207.82"], env=e)
    assert "already applied before this step: update config" in x.value.message \
        or "already applied before this step: create config" in x.value.message
    assert not (home / ".ssh" / "authorized_keys").exists()   # keys go last
    rec = json.loads(e.changes_file.read_text().splitlines()[-1])
    assert rec["kind"] == "setup" and rec["actions"][0]["kind"] == "config"


def test_self_update_and_allow_reboot(env):
    e, _ = env
    cfgp = e.etc / "kevward" / "config.toml"
    cfgp.write_text("[ssh_gate]\nenabled = true\n")
    d = su.setup(ssh_gate=True, self_update=True, allow_reboot=True, env=e)
    keys = [(a["key"], a["action"]) for a in d["actions"] if a["kind"] == "config"]
    assert keys == [("ssh_gate.enabled", "unchanged"), ("ssh_gate.self_update", "update"),
                    ("policy.allow_reboot", "update")]
    c = Config.load(cfgp)
    assert c.ssh_gate.self_update is True and c.policy.allow_reboot is True
    assert len(list(cfgp.parent.glob("config.toml.bak-*"))) == 1   # one write
    assert su.setup(self_update=True, allow_reboot=True, env=e)["changed"] is False


def test_cli_setup_flags(monkeypatch, capsys):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return {"dry_run": True, "changed": False, "actions": []}

    monkeypatch.setattr(su, "setup", fake)
    assert cli.main(["setup", "--self-update", "--allow-reboot", "--dry-run", "--json"]) == 0
    assert seen["self_update"] is True and seen["allow_reboot"] is True


# --- #223: named keys -----------------------------------------------------------------

def test_key_name_prefix(env):
    e, home = env
    su.setup(console_user="ktakahashi", read_key=READ, operate_key=OPERATE,
             key_prefix="fr-sc", env=e)
    text = (home / ".ssh" / "authorized_keys").read_text()
    assert "--key-name fr-sc-read\"" in text and "--key-name fr-sc-operate\"" in text
    sud = (e.etc / "sudoers.d" / su.SUDOERS_NAME).read_text()
    assert "--key-name fr-sc-operate\n" in sud and "*" not in sud


def test_key_name_prefix_rejected(env):
    e, _ = env
    with pytest.raises(su.GateError) as ei:
        su.setup(console_user="ktakahashi", read_key=READ, key_prefix="Bad Name", env=e)
    assert ei.value.code == "bad_request"
