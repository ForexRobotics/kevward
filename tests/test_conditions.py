# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Config-conditional KEV applicability (#86), starting with SSHole."""

from __future__ import annotations

from kevward.integrations import conditions, trends
from kevward.integrations.conditions import HostFacts

SSHOLE = "CVE-2026-123158"


def _facts(libc, usepam):
    f = HostFacts()
    f._cache["libc"] = libc
    f._cache["_sshd_read"] = "1"
    if usepam is not None:
        f._cache["sshd:usepam"] = usepam
    return f


def test_glibc_host_is_not_applicable():
    out = conditions.evaluate([SSHOLE], _facts("glibc", "yes"))
    assert "glibc" in out[SSHOLE]


def test_musl_with_pam_is_not_applicable():
    out = conditions.evaluate([SSHOLE], _facts("musl", "yes"))
    assert "UsePAM" in out[SSHOLE]


def test_musl_without_pam_is_left_alone():
    assert conditions.evaluate([SSHOLE], _facts("musl", "no")) == {}


def test_unreadable_facts_change_nothing():
    assert conditions.evaluate([SSHOLE], _facts(None, None)) == {}


def test_unknown_cve_and_rule_errors_are_ignored(monkeypatch):
    def boom(_f):
        raise RuntimeError("x")

    monkeypatch.setitem(conditions.RULES, "CVE-0000-0001", boom)
    assert conditions.evaluate(["CVE-0000-0001", "CVE-1999-0001"], _facts("glibc", "yes")) == {}


def _entry(cve):
    return trends.KevEntry(cve=cve, vendor="openbsd", product="openssh", name="x",
                           date_added="2026-11-09", due_date="", ransomware=False)


def _run(monkeypatch, labels, na):
    monkeypatch.setattr(trends, "_load_catalog", lambda url=None: [_entry(SSHOLE)])
    monkeypatch.setattr(trends, "_applicability", lambda *a, **k: dict(labels))
    monkeypatch.setattr(conditions, "evaluate", lambda cves, facts=None: dict(na))
    return trends.matching_trends(["openssh"])


def test_trends_marks_unchecked_as_not_applicable(monkeypatch):
    data = _run(monkeypatch, {SSHOLE: "unchecked"}, {SSHOLE: "glibc host"})
    m = data["matches"][0]
    assert m["applicability"] == "not_applicable"
    assert m["applicability_reason"] == "glibc host"
    assert data["not_applicable_count"] == 1


def test_trends_never_overrides_version_verdicts(monkeypatch):
    for verdict in ("fixed", "applicable"):
        data = _run(monkeypatch, {SSHOLE: verdict}, {SSHOLE: "glibc host"})
        m = data["matches"][0]
        assert m["applicability"] == verdict
        assert "applicability_reason" not in m
        assert data["not_applicable_count"] == 0


def test_trends_without_rule_hit_is_unchanged(monkeypatch):
    data = _run(monkeypatch, {SSHOLE: "possible"}, {})
    assert data["matches"][0]["applicability"] == "possible"
    assert data["not_applicable_count"] == 0


def test_html_shows_badge_and_reason():
    from kevward.engine import RunResult
    from kevward.reporting.html import render

    m = {"cve": SSHOLE, "vendor": "openbsd", "product": "openssh", "name": "x",
         "date_added": "2026-11-09", "ransomware": False,
         "applicability": "not_applicable", "applicability_reason": "glibc <host>"}
    t = {"matches": [m], "match_count": 1, "catalog_size": 1, "version_aware": True,
         "not_applicable_count": 1}
    out = render(RunResult(host="h", generated_at="2026-11-10T00:00:00+00:00",
                           os="Linux", attackers={"trends": t}))
    assert "n/a (config)" in out
    assert "glibc &lt;host&gt;" in out
    assert "1 n/a by host config" in out
