# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""docs/ssh-gate-protocol/vectors (#219): kevward's gate answers every vector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kevward import ssh_gate as g

VECTORS = sorted((Path(__file__).parent.parent / "docs" / "ssh-gate-protocol" / "vectors")
                 .glob("*.json"))


def _request(v: dict) -> bytes:
    if "request_hex" in v:
        return bytes.fromhex(v["request_hex"])
    if "request_repeat" in v:
        return (v["request_repeat"]["text"] * v["request_repeat"]["count"]).encode()
    return v["request"].encode()


def test_vectors_exist():
    assert len(VECTORS) >= 10


@pytest.mark.parametrize("vec", VECTORS, ids=lambda p: p.stem)
def test_vector(vec, tmp_path):
    v = json.loads(vec.read_text())
    cfg = tmp_path / "config.toml"
    cfg.write_text(f"[ssh_gate]\nenabled = {str(v['gate_enabled']).lower()}\n"
                   f'truthgate_path = "{tmp_path}/no-truthgate"\n')
    resp = g.handle(_request(v), v["role"], path=cfg, changes_file=tmp_path / "c.jsonl",
                    client="203.0.113.5")
    line = g.dumps(resp)
    assert line.endswith("\n") and "\n" not in line[:-1]
    got = json.loads(line)
    exp = v["expect"]
    assert got["ok"] is exp["ok"], got
    if not exp["ok"]:
        assert set(got) == {"ok", "error", "code"} and got["code"] == exp["code"]
        return
    assert set(got) == {"ok", "data"}
    assert set(exp.get("data_keys", [])) <= set(got["data"])
    for k, val in exp.get("data", {}).items():
        assert got["data"][k] == val
