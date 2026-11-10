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
    assert seen == {"version_budget_s": 90.0, "max_version_checks": 80}
