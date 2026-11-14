# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""[trends] version-check budget is configurable (#66)."""

from __future__ import annotations

from kevward import cli
from kevward.config import Config, TrendsConfig


def test_defaults_match_previous_hardcoded_values():
    t = Config().trends
    assert (t.version_budget_s, t.max_version_checks) == (45.0, 80)


def test_loaded_from_toml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[trends]\nversion_budget_s = 120\nmax_version_checks = 200\nbogus = 1\n")
    t = Config.load(p).trends
    assert (t.version_budget_s, t.max_version_checks) == (120.0, 200)


def test_values_are_clamped():
    t = TrendsConfig(version_budget_s=99999, max_version_checks=-5)
    assert (t.version_budget_s, t.max_version_checks) == (600.0, 0)


def test_cli_passes_budget_to_matching(monkeypatch, tmp_path):
    seen = {}

    def fake(host_terms=None, **kw):
        seen.update(kw)
        return {"catalog_size": 0, "cache_fresh": True, "match_count": 0,
                "ransomware_linked": 0, "matches": []}

    from kevward.integrations import trends
    monkeypatch.setattr(trends, "matching_trends", fake)
    monkeypatch.setattr(cli, "detected_kev_terms", lambda only=None: ["linux"])
    p = tmp_path / "c.toml"
    p.write_text("[trends]\nversion_budget_s = 90\n")
    cli.main(["trends", "-c", str(p)])
    assert seen == {"version_budget_s": 90.0, "max_version_checks": 80, "fetch_workers": 4}


# --- concurrent prefetch and --warm-cache (#66) ------------------------------
import threading  # noqa: E402
import time  # noqa: E402

from kevward.integrations import trends as tr  # noqa: E402
from kevward.integrations import usn  # noqa: E402


def test_fetch_workers_default_and_clamp(tmp_path):
    assert Config().trends.fetch_workers == 4
    assert TrendsConfig(fetch_workers=0).fetch_workers == 1
    assert TrendsConfig(fetch_workers=99).fetch_workers == 16
    p = tmp_path / "c.toml"
    p.write_text("[trends]\nfetch_workers = 8\n")
    assert Config.load(p).trends.fetch_workers == 8


def test_prefetch_runs_in_parallel(monkeypatch):
    live, peak, lock = [0], [0], threading.Lock()

    def slow(cve, timeout=8):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.2)
        with lock:
            live[0] -= 1
        return {"cve": cve}

    monkeypatch.setattr(usn, "fetch_cve", slow)
    t0 = time.monotonic()
    got = tr._prefetch([f"CVE-2000-{i}" for i in range(8)], time.monotonic() + 30, 4)
    assert len(got) == 8 and peak[0] == 4
    assert time.monotonic() - t0 < 1.2  # ~0.4s with 4 workers, 1.6s serial


def test_prefetch_respects_deadline(monkeypatch):
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: time.sleep(0.3) or {})
    t0 = time.monotonic()
    got = tr._prefetch([f"CVE-2000-{i}" for i in range(20)], time.monotonic() + 1.0, 2)
    assert time.monotonic() - t0 < 2.5
    assert len(got) < 20  # the budget stopped it


def test_applicability_uses_prefetched_and_caps_lookups(monkeypatch):
    calls = []
    monkeypatch.setattr(usn, "host_codename", lambda: "jammy")
    monkeypatch.setattr(usn, "installed_source_versions", lambda: {"linux": "5.15.0-1"})
    monkeypatch.setattr(usn, "cache_state", lambda cve: "none")
    monkeypatch.setattr(usn, "cached_cve", lambda cve: None)
    monkeypatch.setattr(usn, "fetch_cve",
                        lambda cve, timeout=8: calls.append(cve) or {"packages": []})
    hits = [tr.KevEntry(f"CVE-2000-{i}", "linux", "kernel", "", "", "", False) for i in range(5)]
    labels = tr._applicability(hits, max_checks=3, budget_s=30, workers=2)
    assert len(calls) == 3
    assert sorted(labels.values()) == ["possible"] * 3 + ["unchecked"] * 2


def test_warm_cache_uses_long_budget(monkeypatch, capsys):
    seen = {}

    def fake(host_terms=None, **kw):
        seen.update(kw)
        return {"catalog_size": 1, "cache_fresh": True, "match_count": 3,
                "ransomware_linked": 0, "matches": [], "version_aware": True,
                "unchecked_count": 0, "cve_cache": {"dir": "/x", "writable": True}}

    monkeypatch.setattr(tr, "matching_trends", fake)
    monkeypatch.setattr(cli, "detected_kev_terms", lambda only=None: ["linux"])
    assert cli.main(["trends", "--warm-cache"]) == 0
    assert seen["version_budget_s"] == cli.WARM_BUDGET_S
    assert seen["max_version_checks"] == cli.WARM_MAX_CHECKS
    assert "still unchecked: 0" in capsys.readouterr().out
