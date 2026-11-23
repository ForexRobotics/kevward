# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#214: the change log records the console's address, not "unknown"."""

from __future__ import annotations

from kevward import setup as su
from kevward import ssh_gate as g


def _proc(tmp_path, tree):
    """tree: {pid: (ppid, {env})}"""
    for pid, (ppid, env) in tree.items():
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in env.items()))
        (d / "stat").write_text(f"{pid} (python3 (x)) S {ppid} 1 1 0 -1\n")
    return tmp_path


def test_from_own_environment():
    env = {"SSH_CONNECTION": "203.0.113.5 50000 192.0.2.10 22"}
    assert g.client_address(env, ppid=1) == "203.0.113.5"


def test_from_ancestor_when_sudo_dropped_it(tmp_path):
    proc = _proc(tmp_path, {
        300: (200, {"SUDO_USER": "ktakahashi"}),                  # sudo
        200: (100, {"SSH_CONNECTION": "2001:db8::5 50000 2001:db8::1 22",
                    "USER": "ktakahashi"}),                      # forced command
        100: (1, {}),                                            # sshd
    })
    assert g.client_address({"SUDO_USER": "ktakahashi"}, ppid=300, proc=proc) == "2001:db8::5"


def test_reason_instead_of_unknown(tmp_path):
    proc = _proc(tmp_path, {300: (1, {})})
    assert g.client_address({"SUDO_USER": "ktakahashi"}, ppid=300, proc=proc) == \
        "unknown (sudo from ktakahashi, SSH_CONNECTION not passed)"
    assert g.client_address({}, ppid=300, proc=proc) == "local"


def test_unreadable_or_odd_proc(tmp_path):
    assert g._ancestor_ssh_connection(4242, proc=tmp_path) == ""
    (tmp_path / "7").mkdir()
    (tmp_path / "7" / "stat").write_text("garbage")
    assert g._ancestor_ssh_connection(7, proc=tmp_path) == ""


def test_loop_is_bounded(tmp_path):
    proc = _proc(tmp_path, {5: (6, {}), 6: (5, {})})
    assert g._ancestor_ssh_connection(5, proc=proc) == ""


def test_sudoers_keeps_ssh_connection(tmp_path):
    from pathlib import Path

    text = su.sudoers_text("ktakahashi", Path("/opt/kevward"))
    assert 'Defaults!/opt/kevward/bin/kevward env_keep += "SSH_CONNECTION"' in text
    assert text.rstrip().endswith(
        "ktakahashi ALL=(root) NOPASSWD: /opt/kevward/bin/kevward ssh-gate --role operate")
