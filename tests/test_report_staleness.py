# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Collectors can tell a fresh report from a stale one (#106)."""

from __future__ import annotations

import json
import re

import pytest

from kevward import cli, engine
from kevward.engine import RunResult
from kevward.reporting.html import render


def test_head_has_machine_readable_metadata():
    html = render(RunResult(host="web-1", generated_at="2026-11-10T22:05:13+00:00",
                            os="Linux"))
    head = html.split("</head>")[0]
    m = re.search(r'<meta name="kevward-generated-at" content="([^"]+)">', head)
    assert m and m.group(1) == "2026-11-10T22:05:13+00:00"
    assert '<meta name="kevward-host" content="web-1">' in head
    assert 'name="kevward-version"' in head


def _quiet(monkeypatch):
    monkeypatch.setattr(engine, "load", lambda only=None: [])
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: {})
    monkeypatch.setattr(cli, "detected_kev_terms", lambda only=None: [])


def test_success_writes_last_run_ok(tmp_path, monkeypatch):
    _quiet(monkeypatch)
    out = tmp_path / "report.html"
    cfgf = tmp_path / "c.toml"
    cfgf.write_text("[update]\ncheck = false\n")
    assert cli.main(["report", "-o", str(out), "-c", str(cfgf)]) == 0
    rec = json.loads((tmp_path / "last-run.json").read_text())
    assert rec["ok"] is True and rec["error"] is None
    assert rec["report"] == str(out)
    assert rec["started_at"] <= rec["finished_at"]


def test_failure_writes_last_run_error_and_reraises(tmp_path, monkeypatch):
    _quiet(monkeypatch)

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(engine, "run", boom)
    monkeypatch.setattr(cli, "run_engine", boom)
    out = tmp_path / "report.html"
    with pytest.raises(OSError):
        cli.main(["report", "-o", str(out)])
    rec = json.loads((tmp_path / "last-run.json").read_text())
    assert rec["ok"] is False and rec["report"] is None
    assert rec["error"].startswith("OSError:") and "No space left" in rec["error"]
    assert not out.exists()


def test_unwritable_dir_never_masks_the_real_error(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_cmd_report", lambda a: (_ for _ in ()).throw(ValueError("x")))
    bad = tmp_path / "file"
    bad.write_text("")  # a file where a directory is expected
    with pytest.raises(ValueError):
        cli.main(["report", "-o", str(bad / "sub" / "report.html")])
