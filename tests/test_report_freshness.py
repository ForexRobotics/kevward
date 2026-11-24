# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#179 apt list freshness, #224 allowed_forced_commands matches, #225 sshd
day over day."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from kevward import audit, cli, engine
from kevward.engine import RunResult
from kevward.plugins import _apt
from kevward.reporting import data as D
from kevward.reporting.html import render

NOW = datetime(2026, 11, 24, 0, 0, tzinfo=timezone.utc)


def _iso(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).isoformat(timespec="seconds")


# --- #179 -----------------------------------------------------------------------

def test_lists_updated_at(tmp_path):
    assert _apt.lists_updated_at(str(tmp_path)) is None
    for name, ago in (("a_InRelease", 30), ("b_Release", 5), ("b_Packages", 0)):
        p = tmp_path / name
        p.write_text("x")
        t = (NOW - timedelta(hours=ago)).timestamp()
        os.utime(p, (t, t))
    assert _apt.lists_updated_at(str(tmp_path)) == _iso(5)   # *Packages ignored


def test_refresh_failed_is_medium_with_hint():
    f = engine.apt_refresh_findings(
        {"state": "failed", "error": "E: Repository 'https://ppa.launchpadcontent.net/ondrej/php"
         "/ubuntu jammy InRelease' changed its 'Label' value from 'PPA for PHP' to 'PPA for "
         "PHP (deprecated)'", "lists_updated_at": _iso(72)}, now=NOW)
    assert len(f) == 1 and f[0].severity.value == "medium" and f[0].service == "apt"
    assert f[0].title.startswith("apt lists could not be refreshed: E: Repository")
    assert "72 h ago" in f[0].detail and "--allow-releaseinfo-change-label" in f[0].detail


def test_stale_lists_without_failure():
    assert engine.apt_refresh_findings({"state": "ok", "lists_updated_at": _iso(1)}, NOW) == []
    f = engine.apt_refresh_findings({"state": "skipped", "lists_updated_at": _iso(60)}, NOW)
    assert f[0].title == "apt lists are stale: last updated 60 h ago"
    assert engine.apt_refresh_findings({}, NOW) == []


def test_header_shows_lists_age(monkeypatch):
    r = RunResult(host="h", generated_at="t", os="Linux")
    r.apt_refresh = {"state": "ok", "lists_updated_at": datetime.now(timezone.utc)
                     .isoformat(timespec="seconds")}
    assert "apt lists: " in render(r) and "(0 h ago)" in render(r)
    assert "apt リスト: " in render(r, lang="ja")
    r.apt_refresh = {"state": "failed", "error": "E: x"}
    assert "apt lists: <b>refresh FAILED</b>" in render(r)


# --- #224 -----------------------------------------------------------------------

STILLE = 'command="/opt/stille-pro/bin/dispatch --worker",restrict ssh-ed25519 BBBB s'


def _keys(tmp_path, *lines):
    p = tmp_path / "authorized_keys"
    p.write_text("\n".join(lines) + "\n")
    p.chmod(0o600)
    return [str(p)]


def test_forced_hits_and_loaded_patterns(tmp_path):
    hits = {"/opt/stille-pro/bin/dispatch": 0}
    f = audit._check_authkeys(list(hits), _keys(tmp_path, STILLE), hits=hits)
    # the pattern has no wildcard for the argument, so it does not match
    assert hits == {"/opt/stille-pro/bin/dispatch": 0}
    assert "loaded, none matched this command: '/opt/stille-pro/bin/dispatch'" in f[0].detail
    hits = {"/opt/stille-pro/bin/dispatch *": 0}
    assert audit._check_authkeys(list(hits), _keys(tmp_path, STILLE), hits=hits) == []
    assert hits == {"/opt/stille-pro/bin/dispatch *": 1}


def test_forced_summary_and_html():
    assert audit.forced_summary({}) == ""
    assert audit.forced_summary({"x *": 0}) == \
        "allowed forced commands: 0 (patterns: x *; no authorized_keys entry matched)"
    assert audit.forced_summary({"a": 2, "b": 0}) == \
        "allowed forced commands: 2 (a; no match: b)"
    r = RunResult(host="h", generated_at="t", os="Linux")
    r.audit = []
    r.audit_allowed_forced = {"x *": 0}
    html = render(r)
    assert "allowed forced commands: 0" in html and "allowed_forced_commands</code>" in html
    assert "（一致なし）" in render(r, lang="ja")
    assert json.loads(r.to_json())["audit_allowed_forced"] == {"x *": 0}


# --- #225 -----------------------------------------------------------------------

def _att(n24, prev24=None):
    a = {"logwatch": {"ssh_total_attempts": 500, "ssh_attempts_24h": n24,
                      "ssh_attempts_7d": 300, "ssh_sources_24h": 9,
                      "ssh_window_start": "2026-11-17T00:00:00+00:00",
                      "ssh_window_end": "2026-11-24T00:00:00+00:00"}}
    if prev24 is not None:
        a["previous"] = {"generated_at": "2026-11-23T07:00:00+00:00", "ssh_failed_24h": prev24}
    return a


def test_surge_finding():
    assert engine.ssh_surge_findings(_att(110, 36))[0].title == \
        "sshd failed logins rose to 110 in the last 24 h (previous report: 36, +206%)"
    assert engine.ssh_surge_findings(_att(60, 36)) == []     # < 2x
    assert engine.ssh_surge_findings(_att(70, 30)) == []     # +40 < 50
    assert engine.ssh_surge_findings(_att(80, 0))[0].title.endswith("(previous report: 0, from 0)")
    assert engine.ssh_surge_findings(_att(80)) == []


def test_html_and_summary_show_previous():
    r = RunResult(host="h", generated_at="t", os="Linux")
    r.attackers = _att(110, 36)
    assert "(previous report: 36, +206%)" in render(r)
    assert "（前回のレポート: 36、+206%）" in render(r, lang="ja")
    s = D.summarize(r)["attack"]
    assert s["previous"]["ssh_failed_24h"] == 36 and s["ssh_failed_24h_change_pct"] == 206
    r.attackers = _att(110)
    assert "previous report" not in render(r)
    assert D.summarize(r)["attack"]["previous"] is None


def test_cli_compares_with_previous_report_json(tmp_path, monkeypatch):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[update]\ncheck = false\n")
    seq = iter([_att(36), _att(110)])
    monkeypatch.setattr(cli, "run_engine",
                        lambda *a, **k: RunResult(host="h", generated_at="t", os="Linux"))
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: next(seq))
    out = tmp_path / "report.html"
    assert cli.main(["report", "-c", str(cfg), "-o", str(out)]) == 0
    first = json.loads((tmp_path / "report.json").read_text())
    assert first["summary"]["attack"]["previous"] is None
    assert cli.main(["report", "-c", str(cfg), "-o", str(out)]) == 0
    second = json.loads((tmp_path / "report.json").read_text())
    assert second["summary"]["attack"]["previous"]["ssh_failed_24h"] == 36
    assert second["summary"]["attack"]["ssh_failed_24h_change_pct"] == 206
    assert any(s["service"] == "sshd" for s in second["services"])
    assert "(previous report: 36, +206%)" in out.read_text()
