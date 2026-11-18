# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#155: [audit] allowed_outbound silences expected outbound connections,
never a shell-owned socket. Fake `ss -tnap` output; no host/root."""

from __future__ import annotations

from kevward import audit as ad
from kevward.config import Config
from kevward.util import Cmd

HDR = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
# www2 on 2026-11-18 (tor = stille-hunter-pro's dark-web check), plus others.
SS = HDR + "\n".join([
    'ESTAB 0 0 160.16.1.2:41234 157.180.60.60:9001 users:(("tor",pid=28994,fd=12))',
    'ESTAB 0 0 160.16.1.2:41236 45.9.60.140:9001 users:(("tor",pid=28994,fd=13))',
    'ESTAB 0 0 160.16.1.2:41238 185.220.101.7:9030 users:(("tor",pid=28994,fd=14))',
    'ESTAB 0 0 160.16.1.2:41240 151.101.1.1:443 users:(("tor",pid=28994,fd=15))',
    'ESTAB 0 0 160.16.1.2:41242 91.198.174.9:9001 users:(("bash",pid=31337,fd=3))',
    'ESTAB 0 0 160.16.1.2:41244 91.198.174.20:5222 users:(("prosody",pid=900,fd=9))',
])


def _run(monkeypatch, patterns):
    monkeypatch.setattr(ad, "run", lambda *a, **k: Cmd(0, SS, ""))
    rules, errors = ad.parse_outbound_allow(patterns)
    assert errors == []
    hits: dict[str, int] = {}
    fs = ad.check_connections(allow=rules, hits=hits)
    return [f.title for f in fs], hits


def test_without_allowlist_tor_9001_is_reported(monkeypatch):
    titles, hits = _run(monkeypatch, [])
    assert sum("tor -> " in t and ":9001" in t for t in titles) == 2
    assert hits == {}


def test_tor_9001_allowed_and_counted(monkeypatch):
    titles, hits = _run(monkeypatch, ["tor:9001"])
    assert not any("tor -> 157.180.60.60:9001" in t or "tor -> 45.9.60.140:9001" in t
                   for t in titles)
    assert hits == {"tor:9001": 2}
    assert any("tor -> 185.220.101.7:9030" in t for t in titles)  # other port still shown
    assert not any(":443" in t for t in titles)  # well-known, as before
    assert ad.allowed_summary(hits) == "allowed outbound: 2 (tor:9001)"


def test_shell_is_never_silenced(monkeypatch):
    titles, hits = _run(monkeypatch, ["*:9001", "bash:*"])
    assert "possible reverse shell: bash -> 91.198.174.9:9001" in titles
    assert "bash:*" not in hits


def test_cidr_restricts_destination(monkeypatch):
    titles, hits = _run(monkeypatch, ["*:5222@91.198.174.0/24"])
    assert hits == {"*:5222@91.198.174.0/24": 1}
    titles, hits = _run(monkeypatch, ["*:5222@8.8.8.0/24"])
    assert any("prosody -> 91.198.174.20:5222" in t for t in titles)


def test_unknown_process_only_matches_star():
    r, _ = ad.parse_outbound_allow(["tor:9001", "*:9001"])
    assert not r[0].matches("", "1.2.3.4", 9001)
    assert r[1].matches("", "1.2.3.4", 9001)
    assert r[0].matches("tor", "1.2.3.4", 9001) and not r[0].matches("tor", "1.2.3.4", 9002)


def test_parse_rejects_malformed_and_too_broad():
    rules, errors = ad.parse_outbound_allow(
        ["tor:9001", "*:*", "nocolon", "tor:abc", "x:1@not-a-cidr", ":9001", "*:*@10.0.0.0/8"])
    assert [r.text for r in rules] == ["tor:9001", "*:*@10.0.0.0/8"]
    assert len(errors) == 5 and any("too broad" in e for e in errors)


def test_audit_reports_bad_entries_and_fills_notes(monkeypatch):
    monkeypatch.setattr(ad, "run", lambda *a, **k: Cmd(0, SS, ""))
    for name in ("check_reverse_ssh", "check_persistence", "_check_proc_origin",
                 "_check_pkg_integrity", "_check_accounts", "_check_suid",
                 "_check_accepted_password"):
        monkeypatch.setattr(ad, name, lambda *a, **k: [])
    notes: dict = {}
    fs = ad.audit(None, ["tor:9001", "*:*"], notes)
    assert notes["allowed_outbound_hits"] == {"tor:9001": 2}
    assert any("allowed_outbound: ignored entry '*:*'" in f.title for f in fs)


def test_config_key_loads(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[audit]\nallowed_outbound = ["tor:9001"]\n')
    assert Config.load(p).audit.allowed_outbound == ["tor:9001"]
    assert Config().audit.allowed_outbound == []


def test_html_shows_summary_line():
    from kevward.engine import RunResult
    from kevward.reporting.html import render
    r = RunResult(host="www2", generated_at="2026-11-18T00:00:00+00:00", os="Ubuntu 24.04")
    r.audit = []
    r.audit_allowed_outbound = {"tor:9001": 2}
    html = render(r)
    assert "allowed outbound: 2 (tor:9001)" in html
    assert "No compromise indicators found." in html
    assert r.to_dict()["audit_allowed_outbound"] == {"tor:9001": 2}
