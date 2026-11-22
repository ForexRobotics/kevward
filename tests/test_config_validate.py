# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#186: settings kevward ignores are reported, not silently dropped."""

from __future__ import annotations

from kevward import cli, engine
from kevward.config import Config, validate_config
from kevward.engine import RunResult
from kevward.model import Severity
from kevward.reporting.html import render

WWW2 = """[audit]
allowed_forced_commands = ["cat /var/log/kevward/report.html"]
[report]
lang = "ja"
allowed_outbound = ["tor:9001"]
"""


def test_www2_case(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(WWW2)
    cfg = Config.load(p)
    assert cfg.load_error is None
    assert cfg.audit.allowed_outbound == []  # really ignored
    assert cfg.warnings == ["unknown setting `allowed_outbound` in [report]; ignored"
                            " — did you mean [audit]?"]


def test_validate_variants():
    assert validate_config({}) == []
    assert validate_config({"audit": {"allowed_outbound": ["tor:9001"]},
                            "report": {"lang": "ja"}, "report_dir": "/x",
                            "policy": {"overrides": {"nginx": {"apply_minor": True}}}}) == []
    w = validate_config({"allowed_outbound": ["x"], "foo": 1, "audti": {"a": 1},
                         "trends": {"fetch_worker": 2}, "report": {"report_dir": "/x"},
                         "policy": {"overrides": {"nginx": {"aply_minor": True}, "x": 1}},
                         "audit": "oops"})
    assert "`allowed_outbound` is not a top-level setting; ignored — did you mean [audit]?" in w
    assert "unknown table or setting `foo`; ignored" in w
    assert "unknown table or setting `audti`; ignored" in w
    assert "unknown setting `fetch_worker` in [trends]; ignored" in w
    assert ("unknown setting `report_dir` in [report]; ignored — did you mean the top "
            "level (before any [table])?") in w
    assert "unknown setting `aply_minor` in [policy.overrides.nginx]; ignored" in w
    assert "[policy.overrides.x] should be a table; ignored" in w
    assert "`audit` should be a table ([audit]); ignored" in w
    assert Config.from_dict({"audit": "oops"}).audit.allowed_outbound == []


def test_surfaced_in_cli_report_and_json(tmp_path, monkeypatch, capsys):
    p = tmp_path / "c.toml"
    p.write_text(WWW2)
    cfg = Config.load(p)
    rep = engine.config_warning_report(cfg)
    [f] = rep.findings
    assert f.severity is Severity.MEDIUM and "1 setting in" in f.title
    assert "did you mean [audit]" in f.detail

    r = RunResult("www2", "t", "Linux", config_source=str(p),
                  config_warnings=list(cfg.warnings))
    r.audit = []
    r.audit_rules = cli.audit_rule_counts(cfg)
    assert r.audit_rules == {"allowed_outbound": 0, "allowed_forced_commands": 1}
    d = r.to_dict()
    assert d["config_warnings"] == cfg.warnings and d["audit_rules"]["allowed_outbound"] == 0
    ja = render(r, lang="ja")
    assert "（無視された設定 1 件 — 指摘を参照）" in ja
    assert "読み込んだルール: allowed_outbound 0 件 · allowed_forced_commands 1 件" in ja
    en = render(r)
    assert "(1 ignored setting — see findings)" in en

    class A:
        config = str(p)
        services = None
    cli._mkconfig(A())
    assert "did you mean [audit]" in capsys.readouterr().err


def test_example_config_has_no_ignored_settings():
    from pathlib import Path

    from kevward.config import tomllib
    p = Path(__file__).resolve().parent.parent / "config.example.toml"
    assert Config.from_dict(tomllib.loads(p.read_text())).warnings == []
