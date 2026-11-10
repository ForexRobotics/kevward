# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""A broken config.toml must not silently stop reports (#104); the config in
use is visible (#105)."""

from __future__ import annotations

import pytest

from kevward import cli, engine
from kevward.config import Config
from kevward.engine import RunResult
from kevward.reporting.html import render

# What actually landed on a host on 2026-11-10: a pasted heredoc, not TOML.
BROKEN = "sudo tee /etc/kevward/config.toml >/dev/null <<'EOF'\n[trends]\nEOF\n"


def _write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return p


def test_valid_file_records_source(tmp_path):
    p = _write(tmp_path, "[trends]\nversion_budget_s = 120\n")
    cfg = Config.load(p)
    assert cfg.source == p and cfg.load_error is None
    assert cfg.trends.version_budget_s == 120.0


def test_no_file_means_defaults_without_error(tmp_path, monkeypatch):
    monkeypatch.setattr("kevward.config.DEFAULT_PATHS", [tmp_path / "nope.toml"])
    cfg = Config.load()
    assert cfg.source is None and cfg.load_error is None


def test_malformed_toml_falls_back_to_defaults(tmp_path):
    p = _write(tmp_path, BROKEN)
    cfg = Config.load(p)
    assert cfg.source == p
    assert "not valid TOML" in cfg.load_error and "line 1" in cfg.load_error
    assert cfg.trends.version_budget_s == 45.0  # defaults
    assert "sudo tee" not in cfg.load_error      # never echo file contents


def test_wrong_type_falls_back_to_defaults(tmp_path):
    p = _write(tmp_path, '[trends]\nversion_budget_s = "abc"\n')
    cfg = Config.load(p)
    assert cfg.load_error == "invalid value: ValueError"
    assert "abc" not in cfg.load_error
    assert cfg.trends.version_budget_s == 45.0


def test_engine_adds_high_finding_and_source(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "load", lambda only=None: [])
    p = _write(tmp_path, BROKEN)
    res = engine.run(Config.load(p))
    assert res.config_source == str(p) and res.config_error
    f = res.services[-1].findings[0]
    assert f.severity.value == "high" and "running with defaults" in f.title
    d = res.to_dict()
    assert d["config_source"] == str(p) and d["config_error"]


def _render(**kw):
    return render(RunResult(host="h", generated_at="2026-11-10T00:00:00+00:00",
                            os="Linux", **kw))


def test_header_shows_config_source():
    assert "config: defaults" in _render()
    assert "config: /etc/kevward/config.toml<" in _render(
        config_source="/etc/kevward/config.toml")
    out = _render(config_source="/etc/kevward/config.toml", config_error="not valid TOML")
    assert "UNREADABLE" in out


def test_report_command_warns_and_continues(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(engine, "load", lambda only=None: [])
    p = _write(tmp_path, BROKEN)
    cli.main(["check", "-c", str(p)])
    out = capsys.readouterr()
    assert "warning:" in out.err and "built-in defaults" in out.err
    assert "HIGH" in out.out


@pytest.mark.parametrize("argv", [
    ["apply", "--yes"],
    ["firewall", "apply", "--yes"],
    ["firewall", "flush", "--yes"],
    ["schedule-reboot"],
])
def test_side_effecting_commands_refuse(tmp_path, argv, capsys):
    p = _write(tmp_path, BROKEN)
    with pytest.raises(SystemExit) as e:
        cli.main([*argv, "-c", str(p)])
    assert e.value.code == 2
    assert "refused:" in capsys.readouterr().err


def test_dry_runs_still_work(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(engine, "load", lambda only=None: [])
    p = _write(tmp_path, BROKEN)
    cli.main(["apply", "-c", str(p)])  # dry run: read-only, so it continues
    assert "DRY RUN" in capsys.readouterr().out
