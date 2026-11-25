# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#211: report.json, the count meta tags, last-run counts and ssh-gate
``report.get`` format=data."""

from __future__ import annotations

import json
import re

from kevward import cli
from kevward import ssh_gate as g
from kevward.engine import RunResult
from kevward.model import Finding, FindingKind, ServiceReport, Severity
from kevward.reporting import data as D
from kevward.reporting.html import render


def _upd(svc, pkg, sev=Severity.HIGH):
    return Finding(service=svc, kind=FindingKind.SECURITY_UPDATE, severity=sev,
                   title=f"{pkg} 1 → 2", ref=pkg, current_version="1", fixed_version="2")


def _result():
    apache = [_upd("apache", "apache2"), _upd("apache", "apache2-bin")]
    apt = [_upd("apt", p) for p in ("apache2", "apache2-bin", "apache2-data")]
    apt.append(_upd("apt", "openssl", Severity.CRITICAL))
    apt.append(Finding(service="apt", kind=FindingKind.CONFIG, severity=Severity.MEDIUM,
                       title="Reboot required"))
    r = RunResult(host="web-01", generated_at="2026-11-23T00:00:00+00:00", os="Linux",
                  services=[ServiceReport("apache", True, findings=apache),
                            ServiceReport("apt", True, findings=apt),
                            ServiceReport("nginx", False, findings=[_upd("nginx", "x")])])
    r.audit = [Finding(service="audit", kind=FindingKind.CONFIG, severity=Severity.LOW,
                       title="unexpected listener"),
               Finding(service="audit", kind=FindingKind.CONFIG, severity=Severity.HIGH,
                       title="forced command")]
    r.attackers = {
        "fail2ban": {"total_ban_events": 42, "unique_ips": 9, "live_total": 3,
                     "top_offenders": [["192.0.2.1", 20], ["198.51.100.2", 22]]},
        "logwatch": {"ssh_total_attempts": 1234, "ssh_unique_sources": 55,
                     "ssh_attempts_24h": 80, "ssh_attempts_7d": 500,
                     "ssh_window_start": "2026-11-16T00:00:00+09:00",
                     "ssh_window_end": "2026-11-23T08:00:00+09:00",
                     "ssh_failed_logins": [["203.0.113.9", 300]]},
        "firewall": {"blocklist4": [100, 6000], "blocklist6": [5, 400],
                     "blockcidr4": [20, 1200]},
        "firewall_since": 1763856000,
        "trends": {"version_aware": True, "match_count": 5, "applicable_count": 2,
                   "unchecked_count": 1, "fixed_count": 1, "not_applicable_count": 0,
                   "na_release_count": 1, "ransomware_linked": 1,
                   "matches": [
                       {"cve": "CVE-2025-0001", "applicability": "applicable"},
                       {"cve": "CVE-2025-0002", "applicability": "applicable"},
                       {"cve": "CVE-2025-0003", "applicability": "unchecked"},
                       {"cve": "CVE-2024-0004", "applicability": "fixed"},
                       {"cve": "CVE-2016-0005", "applicability": "na_release"}]},
    }
    return r


def _chips(html: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"(critical|high|medium|low|info): <b>(\d+)</b>", html)}


def _meta(html: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r'<meta name="kevward-count-([a-z-]+)" content="(\d+)">', html)}


def test_summary_matches_html():
    r = _result()
    html = render(r)
    s = D.summarize(r)
    # apache2/apache2-bin hidden under apt (counted once); audit included
    assert s["counts"] == {"critical": 1, "high": 4, "medium": 1, "low": 1, "info": 0}
    assert s["counts"] == _chips(html)
    assert s["act_now"] == 5 and "to act on (critical/high): <b>5</b>" in html
    assert s["apt_rows_deduplicated"] == 2 and s["audit_indicators"] == 2
    meta = _meta(html)
    assert {k: meta[k] for k in s["counts"]} == s["counts"]
    assert meta["act-now"] == 5 and meta["kev-applicable"] == 2


def test_summary_kev_and_attack():
    s = D.summarize(_result())
    assert s["kev"] == {"version_aware": True, "matches": 5, "applicable": 2, "unchecked": 1,
                        "fixed": 1, "na_config": 0, "na_release": 1, "ransomware_linked": 1,
                        "applicable_cves": ["CVE-2025-0001", "CVE-2025-0002"],
                        "unchecked_cves": ["CVE-2025-0003"]}
    a = s["attack"]
    assert a["fail2ban_bans_total"] == 42 and a["fail2ban_banned_now"] == 3
    assert a["ssh_failed_total"] == 1234 and a["ssh_failed_24h"] == 80
    assert a["ssh_window"]["start"].startswith("2026-11-16")
    assert a["fw_drops"] == {"evidence": 105, "cidr": 20, "total": 125, "since": 1763856000}
    html = render(_result())
    assert "evidence blocklist <b>105</b>" in html and "total <b>125</b>" in html


def test_empty_result():
    s = D.summarize(RunResult(host="h", generated_at="t", os="Linux"))
    assert s["counts"] == dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    assert s["kev"] is None and s["audit_indicators"] is None
    assert s["attack"]["fw_drops"] is None and s["attack"]["ssh_failed_total"] == 0


def test_report_data_is_run_result_plus_summary():
    r = _result()
    d = D.report_data(r)
    assert d["schema_version"] == 1
    assert {k: v for k, v in d.items()
            if k not in ("summary", "last_apply")} == \
        json.loads(r.to_json())
    assert d["attackers"]["fail2ban"]["top_offenders"][1] == ["198.51.100.2", 22]


def test_cli_writes_report_json_and_last_run_counts(tmp_path, monkeypatch):
    import stat

    cfg = tmp_path / "c.toml"
    cfg.write_text("[update]\ncheck = false\n")
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: _result())
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: _result().attackers)
    out = tmp_path / "rep" / "report.html"
    assert cli.main(["report", "-c", str(cfg), "-o", str(out)]) == 0
    data = json.loads((tmp_path / "rep" / "report.json").read_text())
    assert data["summary"]["counts"] == _chips(out.read_text())
    assert stat.S_IMODE((tmp_path / "rep" / "report.json").stat().st_mode) == 0o644
    assert not list((tmp_path / "rep").glob(".*.tmp"))
    last = json.loads((tmp_path / "rep" / "last-run.json").read_text())
    assert last["ok"] and last["counts"] == {"critical": 1, "high": 4, "medium": 1, "low": 1,
                                             "info": 0, "act_now": 5, "kev_applicable": 2}


def test_report_json_failure_keeps_html(tmp_path, monkeypatch, capsys):
    from kevward.reporting import data as data_mod

    cfg = tmp_path / "c.toml"
    cfg.write_text("[update]\ncheck = false\n")
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: _result())
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: {})

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(data_mod, "write_report_data", boom)
    out = tmp_path / "report.html"
    assert cli.main(["report", "-c", str(cfg), "-o", str(out)]) == 0
    assert out.exists() and "could not write" in capsys.readouterr().err
    assert json.loads((tmp_path / "last-run.json").read_text())["counts"] is None


# --- ssh-gate --------------------------------------------------------------------

def _gate(tmp_path, args):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'report_dir = "{tmp_path / "rep"}"\n[ssh_gate]\nenabled = true\n')
    req = json.dumps({"op": "report.get", "args": args}).encode()
    return g.handle(req, "read", path=cfg, changes_file=tmp_path / "c.jsonl")


def test_gate_report_get_data(tmp_path):
    assert _gate(tmp_path, {"format": "data"})["code"] == "not_found"
    D.write_report_data(tmp_path / "rep" / "report.json", _result())
    r = _gate(tmp_path, {"format": "data"})
    assert r["ok"] and r["data"]["format"] == "data"
    assert r["data"]["content"]["summary"]["act_now"] == 5
    assert r["data"]["path"].endswith("report.json") and len(r["data"]["sha256"]) == 64
    assert _gate(tmp_path, {"format": "xml"})["code"] == "bad_request"
