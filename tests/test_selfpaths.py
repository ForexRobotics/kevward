# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#222: gate.selfpaths."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from kevward import selfpaths as sp
from kevward import ssh_gate as g

SRC = Path(sp.__file__).parent
# argv[0] literals: run(["x", …]), runner([…]), r([…]), argv = ["x", …],
# for cmd in (["x", …], …)
_CALL = re.compile(r'(?:\b(?:run|run_stream|runner|r)\(|(?:argv|args|cmd)\s*=\s*|in \()'
                   r'\s*\[\s*"([^"]+)"')


def test_command_list_covers_the_code():
    used = set()
    for f in SRC.rglob("*.py"):
        used |= set(_CALL.findall(f.read_text()))
    if "_nft(" in "".join(f.read_text() for f in SRC.rglob("*.py")):
        used.add("nft")
    used = {u for u in used if not u.startswith("-")}
    missing = used - set(sp.COMMANDS)
    assert not missing, f"add to selfpaths.COMMANDS: {sorted(missing)}"


def test_shebang(tmp_path):
    f = tmp_path / "kevward"
    f.write_text("#!/opt/kevward/bin/python3\nimport sys\n")
    assert sp.shebang(str(f)) == "/opt/kevward/bin/python3"
    f.write_text("#!/usr/bin/env python3\n")
    assert sp.shebang(str(f)) and sp.shebang(str(f)).endswith("python3")
    f.write_text("echo\n")
    assert sp.shebang(str(f)) is None


def test_selfpaths_venv_layout(tmp_path):
    (tmp_path / "bin").mkdir()
    launcher = tmp_path / "bin" / "kevward"
    launcher.write_text(f"#!{sys.executable}\n")
    d = sp.selfpaths(environ={}, prefix=tmp_path)
    # install_info only says "venv" for the running prefix; check the shape.
    assert d["interpreter"]["realpath"] == os.path.realpath(d["interpreter"]["path"])
    assert d["interpreter"]["sha256"] and len(d["interpreter"]["sha256"]) == 64
    assert d["launcher_sha256"] is None or len(d["launcher_sha256"]) == 64
    assert Path(d["package_dir"], "selfpaths.py").exists()
    assert set(d["commands"]) == set(sp.COMMANDS)
    assert re.match(d["apply_units"]["transient_pattern"],
                    "kevward-apply-20261125T010000Z-a1b2c3.service")


def test_selfpaths_op(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[ssh_gate]\nenabled = true\n")
    resp = g.handle(b'{"op":"gate.selfpaths"}', "read", path=cfg,
                    changes_file=tmp_path / "c.jsonl", client="203.0.113.5")
    assert resp["ok"] and resp["data"]["version"]
    assert "gate.selfpaths" in g.READ_OPS
