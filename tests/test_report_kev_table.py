# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The KEV table lists every match (it used to stop silently at 30)."""

from kevward.engine import RunResult
from kevward.reporting.html import render


def _match(i):
    return {"cve": f"CVE-2026-{1000 + i}", "vendor": "linux", "product": "kernel",
            "name": "x", "date_added": "2026-01-01", "ransomware": False,
            "applicability": "possible"}


def test_all_51_matches_rendered():
    trends = {"matches": [_match(i) for i in range(51)], "match_count": 51,
              "catalog_size": 1769, "version_aware": True}
    html = render(RunResult(host="h", generated_at="2026-11-07T00:00:00+00:00",
                            os="Linux", attackers={"trends": trends}))
    assert "CVE-2026-1050" in html          # the 51st row
    assert html.count("<td class='cve'>CVE-2026-") == 51
