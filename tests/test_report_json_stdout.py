# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""`report --json > posture.json` must produce a valid JSON file (#113)."""

from __future__ import annotations

import json

from kevward import cli, engine


def _quiet(monkeypatch, tmp_path):
    monkeypatch.setattr(engine, "load", lambda only=None: [])
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: {})
    monkeypatch.setattr(cli, "detected_kev_terms", lambda only=None: [])
    cfgf = tmp_path / "c.toml"
    cfgf.write_text("[update]\ncheck = false\n")  # no PyPI lookup: stay offline
    return cfgf


def test_report_json_stdout_is_pure_json(tmp_path, monkeypatch, capsys):
    cfgf = _quiet(monkeypatch, tmp_path)
    out = tmp_path / "report.html"
    assert cli.main(["report", "--json", "-o", str(out), "-c", str(cfgf)]) == 0
    cap = capsys.readouterr()
    data = json.loads(cap.out)
    assert "kevward_version" in data and "services" in data
    assert f"wrote {out}" in cap.err
    assert out.exists()


def test_report_without_json_still_prints_wrote_on_stdout(tmp_path, monkeypatch, capsys):
    cfgf = _quiet(monkeypatch, tmp_path)
    out = tmp_path / "report.html"
    assert cli.main(["report", "-o", str(out), "-c", str(cfgf)]) == 0
    cap = capsys.readouterr()
    assert cap.out.strip() == f"wrote {out}"
    assert "wrote" not in cap.err
