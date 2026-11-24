# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#192: kevward uninstall against a temp root and a fake nft/systemctl."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kevward import cli
from kevward import uninstall as un
from kevward.ssh_gate import GateError
from kevward.util import Cmd

NOW = datetime(2026, 11, 22, 7, 0, 0, tzinfo=timezone.utc)
NFT = (Path(__file__).parent / "data" / "nft-kevward-tables.txt").read_text()
KEVWARD_T = NFT.split("table inet kevward_harden")[0]
HARDEN_T = "table inet kevward_harden" + NFT.split("table inet kevward_harden")[1]
GATE_R = ('command="/opt/kevward/bin/kevward ssh-gate --role read",restrict '
          "ssh-ed25519 AAAAr console-read")
GATE_O = ('command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate",restrict '
          "ssh-ed25519 AAAAo console-operate")
COLLECT = 'command="cat /var/log/kevward/report.html",restrict ssh-rsa AAAAc collector'
PERSONAL = "ssh-ed25519 AAAAp me@pc"


class FakeHost:
    """Records commands; answers `nft list table` from a dict."""

    def __init__(self, tables):
        self.tables, self.calls = dict(tables), []

    def __call__(self, args, timeout=120, **k):
        self.calls.append(args)
        if args[:2] == ["nft", "--version"]:
            return Cmd(0, "nftables v1.0.9", "")
        if args[:3] == ["nft", "list", "table"]:
            t = self.tables.get(args[-1])
            return Cmd(0, t, "") if t else Cmd(1, "", "No such file or directory")
        if args[:3] == ["nft", "delete", "table"]:
            self.tables.pop(args[-1], None)
        return Cmd(0, "", "")


@pytest.fixture
def host(tmp_path):
    etc = tmp_path / "etc"
    for d in ("systemd/system/kevward-report.timer.d", "kevward", "sysctl.d", "sudoers.d",
              "fail2ban/jail.d"):
        (etc / d).mkdir(parents=True)
    for u in ("kevward-report.timer", "kevward-report.service", "kevward-firewall.service",
              "kevward-harden.service"):
        (etc / "systemd/system" / u).write_text("[Unit]\n")
    (etc / "systemd/system/kevward-report.timer.d/50-kevward.conf").write_text("x")
    (etc / "systemd/system/other.service").write_text("[Unit]\n")
    for f in ("kevward/firewall.nft", "kevward/harden.nft", "kevward/config.toml",
              "sysctl.d/99-kevward-mptcp.conf", "sudoers.d/kevward-ssh-gate",
              "fail2ban/jail.d/kevward-console.local"):
        (etc / f).write_text("x\n")
    home = tmp_path / "home" / "ktakahashi"
    (home / ".ssh").mkdir(parents=True)
    ak = home / ".ssh" / "authorized_keys"
    ak.write_text("\n".join([PERSONAL, GATE_R, COLLECT, GATE_O]) + "\n")
    os.chmod(ak, 0o600)
    prefix = tmp_path / "opt" / "kevward"
    (prefix / "bin").mkdir(parents=True)
    launcher = tmp_path / "usr-local-bin-kevward"
    launcher.write_text(f'#!/bin/sh\nexec {prefix}/bin/kevward "$@"\n')
    data = tuple(tmp_path / "var" / d for d in ("log", "lib", "cache"))
    for d in data:
        d.mkdir(parents=True)
    fake = FakeHost({"kevward": KEVWARD_T, "kevward_harden": HARDEN_T})
    env = un.Env(etc=etc, prefix=prefix, launcher=launcher, data_dirs=data,
                 changes_file=tmp_path / "var" / "lib" / "changes.jsonl",
                 homes=lambda: [home], runner=fake, now=NOW, is_root=lambda: True)
    return env, fake, ak


def test_real_nft_listing_is_safe():
    assert un.nft_table_safe(NFT) == []
    assert un.nft_table_safe(NFT.replace("policy accept;", "policy drop;", 1))
    assert un.nft_table_safe(NFT.replace("ip saddr @allow4 accept", "tcp dport 22 drop"))
    assert un.nft_table_safe(NFT.replace("ip saddr @allow4 accept", "jump other"))


def test_dry_run_is_default_and_changes_nothing(host):
    env, fake, ak = host
    d = un.uninstall(env=env)
    assert d["dry_run"] is True
    kinds = [a["kind"] for a in d["actions"]]
    assert kinds.count("nft_table") == 2 and kinds.count("unit") == 4
    assert "program" in kinds and "launcher" in kinds and "purge" not in kinds
    [akact] = [a for a in d["actions"] if a["kind"] == "authorized_keys"]
    assert akact["lines"] == 2                    # gate lines only, not the collector
    assert not any(c[:2] in (["systemctl", "disable"], ["nft", "delete"]) for c in fake.calls)
    assert len(ak.read_text().splitlines()) == 4 and env.prefix.exists()


def test_yes_removes_in_safe_order(host):
    env, fake, ak = host
    d = un.uninstall(yes=True, env=env)
    assert d["errors"] == []
    etc = env.etc
    assert not (etc / "systemd/system/kevward-report.timer").exists()
    assert not (etc / "systemd/system/kevward-report.timer.d").exists()
    assert (etc / "systemd/system/other.service").exists()
    assert not (etc / "kevward/firewall.nft").exists()
    assert not (etc / "sudoers.d/kevward-ssh-gate").exists()
    assert (etc / "kevward/config.toml").exists()          # kept without --purge
    assert ak.read_text().splitlines() == [PERSONAL, COLLECT]
    assert oct(ak.stat().st_mode & 0o777) == "0o600"
    assert not env.prefix.exists() and not env.launcher.exists()
    assert all(d.exists() for d in env.data_dirs)
    # persistence (units disabled, files gone) before the tables are deleted
    order = [" ".join(c[:3]) for c in fake.calls]
    first_delete = order.index("nft delete table")
    assert max(i for i, c in enumerate(order) if c.startswith("systemctl disable")) \
        < first_delete
    assert fake.tables == {}
    rec = json.loads(env.changes_file.read_text())
    assert rec["kind"] == "uninstall"


def test_collector_keys_and_purge(host):
    env, _, ak = host
    un.uninstall(yes=True, purge=True, remove_collector_keys=True, env=env)
    assert ak.read_text().splitlines() == [PERSONAL]
    assert not (env.etc / "kevward").exists()
    assert not any(d.exists() for d in env.data_dirs)


@pytest.mark.parametrize("tamper", [
    lambda t: t.replace("policy accept;", "policy drop;", 1),
    lambda t: t.replace("ip saddr @allow4 accept", "tcp dport 22 accept"),
])
def test_conflict_on_unexpected_rules_changes_nothing(host, tamper):
    env, fake, ak = host
    fake.tables["kevward"] = tamper(KEVWARD_T)
    with pytest.raises(GateError) as e:
        un.uninstall(yes=True, env=env)
    assert e.value.code == "conflict" and "nothing was changed" in e.value.message
    assert (env.etc / "kevward/firewall.nft").exists() and env.prefix.exists()
    assert len(ak.read_text().splitlines()) == 4
    assert not any(c[:2] == ["systemctl", "disable"] for c in fake.calls)


def test_conflict_when_boot_config_mentions_kevward(host):
    env, _, _ = host
    (env.etc / "nftables.conf").write_text('include "/etc/kevward/firewall.nft"\n')
    with pytest.raises(GateError) as e:
        un.uninstall(yes=True, env=env)
    assert e.value.code == "conflict" and "next boot" in e.value.message


def test_not_root_and_foreign_launcher(host):
    env, _, _ = host
    env.is_root = lambda: False
    with pytest.raises(GateError) as e:
        un.uninstall(yes=True, env=env)
    assert e.value.code == "forbidden"
    assert un.uninstall(env=env)["dry_run"] is True      # dry run needs no root
    env.launcher.write_text("#!/bin/sh\necho someone else's tool\n")
    kinds = [a["kind"] for a in un.uninstall(env=env)["actions"]]
    assert "launcher" not in kinds


def test_strip_gate_lines():
    text = "\n".join([PERSONAL, GATE_R, COLLECT, GATE_O,
                      'command="/opt/kevward/bin/kevward ssh-gate --role operate; sh" x y z'])
    new, n = un.strip_gate_lines(text, collector=False)
    assert n == 2 and "; sh" in new          # not a gate line we wrote: kept, audit flags it


def test_cli_json(monkeypatch, capsys):
    monkeypatch.setattr(un, "uninstall", lambda **k: {"dry_run": True, "purge": False,
                                                       "actions": []})
    rc = cli.main(["uninstall", "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["data"]["dry_run"] is True


# --- #234: several timed elements per line ----------------------------------------

def test_timed_elements_several_per_line_are_ours():
    # real nft 1.0.9 shape (www2, 2026-11-24): several timed elements per line
    e1 = "2.57.122.74 timeout 14d expires 9d20h28m23s400ms"
    e2 = "2.57.122.76 timeout 14d expires 9d20h28m23s400ms"
    e3 = "45.148.10.61 timeout 14d expires 13d1h2m3s"
    e4 = "195.178.110.218 timeout 14d expires 2d4h"
    listing = "\n".join([
        "table inet kevward {",
        "\tset block4 {",
        "\t\ttype ipv4_addr",
        "\t\tflags interval,timeout",
        "\t\tauto-merge",
        f"\t\telements = {{ {e1}, {e2},",
        f"\t\t\t     {e3}, {e4} }}",
        "\t}",
        "\tset block6 {",
        "\t\ttype ipv6_addr",
        "\t\tflags interval,timeout",
        "\t\telements = { 2001:db8::1 timeout 14d expires 3d, 2001:db8::2 timeout 14d "
        "expires 1h }",
        "\t}",
        "\tset cidr4 {",
        "\t\ttype ipv4_addr",
        "\t\tflags interval",
        "\t\telements = { 10.0.0.0/8, 192.0.2.0/24 }",
        "\t}",
        "}",
    ]) + "\n"
    assert un.nft_table_safe(listing) == []
    assert un.nft_table_safe(listing.replace("2d4h }", "2d4h }\n\t\tip saddr 1.2.3.4 accept"))
    assert un.nft_table_safe("elements = { 1.2.3.4 timeout 14d; drop }")
    assert un.nft_table_safe("elements = { 1.2.3.4 } jump other")


# --- #236: uninstall saves what setup put there; setup --restore puts it back ------

def test_snapshot_and_restore_roundtrip(tmp_path):
    import json

    from kevward import setup as su

    etc = tmp_path / "etc"
    home = tmp_path / "home" / "ktakahashi"
    (home / ".ssh").mkdir(parents=True)
    (etc / "fail2ban" / "jail.d").mkdir(parents=True)
    read = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCr fr-security-centre"
    op = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDB fr-security-centre-operate"
    (home / ".ssh" / "authorized_keys").write_text(
        "ssh-ed25519 AAAAC3Nza me@pc\n"
        f'command="/opt/kevward/bin/kevward ssh-gate --role read",restrict {read}\n'
        f'command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate",restrict {op}\n')
    (etc / "fail2ban" / "jail.d" / su.F2B_NAME).write_text(
        "# x\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 124.44.207.82/32\n")
    state = tmp_path / "schedule.json"
    state.write_text('{"created": [], "at": "05:30", "jitter": "10min"}')
    snap = su.snapshot_host(etc, [("ktakahashi", home)], state)
    assert snap == {"version": 1,
                    "users": [{"user": "ktakahashi", "read_key": read, "operate_key": op}],
                    "timer": {"at": "05:30", "jitter": "10min"},
                    "fail2ban_ignore": ["124.44.207.82/32"]}
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    seen = []

    def fake_setup(**kw):
        seen.append(kw)
        return {"dry_run": kw["dry_run"], "changed": True,
                "actions": [{"kind": "x", "path": "p", "action": "create"}]}

    real = su.setup
    su.setup = fake_setup
    try:
        out = su.restore(path=path, dry_run=True)
    finally:
        su.setup = real
    assert out["changed"] and out["restored_from"] == str(path)
    (kw,) = seen
    assert kw["console_user"] == "ktakahashi" and kw["read_key"] == read
    assert kw["operate_key"] == op and kw["ssh_gate"] is True and kw["timer"] is True
    assert (kw["timer_at"], kw["timer_jitter"]) == ("05:30", "10min")
    assert kw["fail2ban_ignore"] == ["124.44.207.82/32"]


def test_restore_without_snapshot(tmp_path):
    import pytest

    from kevward import setup as su
    from kevward.ssh_gate import GateError

    with pytest.raises(GateError) as e:
        su.restore(path=tmp_path / "none.json")
    assert e.value.code == "not_found" and "--purge" in e.value.message


def test_uninstall_writes_snapshot_first(host):
    env, _, ak = host
    d = un.uninstall(env=env)
    assert d["actions"][0] == {"kind": "snapshot",
                               "target": str(env.data_dirs[1] / "setup-snapshot.json")}
    assert not (env.data_dirs[1] / "setup-snapshot.json").exists()   # dry run writes nothing
    un.uninstall(yes=True, env=env)
    snap = json.loads((env.data_dirs[1] / "setup-snapshot.json").read_text())
    assert [bool(u["read_key"] or u["operate_key"]) for u in snap["users"]] == [True]
    assert oct((env.data_dirs[1] / "setup-snapshot.json").stat().st_mode & 0o777) == "0o600"
    # --purge keeps nothing, so it promises no snapshot
    assert all(a["kind"] != "snapshot"
               for a in un.uninstall(purge=True, env=env)["actions"])
