# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#74: 'n/a (release)' for KEV rows Ubuntu's own data rules out for this
release. Pure tests: no network, dpkg or root. The rule must stay
conservative — it only ever turns 'possible' into 'na_release'."""

from __future__ import annotations

from kevward.integrations import trends as tr
from kevward.integrations import usn

JAMMY_KERNEL = {"linux": "5.15.0-203.213"}


def _linux(*statuses):
    return {"packages": [{"name": "linux", "statuses": [
        {"release_codename": rel, "status": st, "description": desc}
        for rel, st, desc in statuses
    ]}]}


# Dirty COW-style: tracked only on releases older than jammy, all fixed there.
_OLD_FIXED = _linux(("trusty", "released", "3.13.0-100.147"),
                    ("xenial", "released", "4.4.0-45.66"),
                    ("bionic", "not-affected", ""))


def test_kernel_series():
    assert usn._kernel_series("5.15.0-203.213") == (5, 15)
    assert usn._kernel_series("4.4.0-45.66") == (4, 4)
    assert usn._kernel_series("6.8.0-149.149") == (6, 8)
    assert usn._kernel_series("") is None
    assert usn._kernel_series("abc") is None


def test_old_kernel_cve_fixed_before_this_series_is_na_release():
    assert usn.classify_cve(_OLD_FIXED, "jammy", JAMMY_KERNEL) == "possible"
    why = usn.release_na_reason(_OLD_FIXED, "jammy", JAMMY_KERNEL)
    assert why and "4.4.0-45.66" in why and "xenial" in why and "jammy" in why


def test_not_affected_on_this_release_is_na_release():
    data = _linux(("noble", "not-affected", "6.8.0-1.1"))
    assert usn.classify_cve(data, "noble", {"linux": "6.8.0-149.149"}) == "possible"
    why = usn.release_na_reason(data, "noble", {"linux": "6.8.0-149.149"})
    assert why == "Ubuntu marks linux not affected on noble (6.8.0-1.1)"


def test_unsettled_older_release_keeps_possible():
    for bad in ("needed", "pending", "deferred", "ignored"):
        data = _linux(("xenial", "released", "4.4.0-45.66"), ("bionic", bad, ""))
        assert usn.release_na_reason(data, "jammy", JAMMY_KERNEL) is None, bad


def test_fix_on_same_or_newer_series_keeps_possible():
    data = _linux(("focal", "released", "5.15.0-50.56"))  # focal HWE on 5.15
    assert usn.release_na_reason(data, "jammy", JAMMY_KERNEL) is None


def test_unparseable_or_missing_fix_keeps_possible():
    assert usn.release_na_reason(_linux(("xenial", "released", "")),
                                 "jammy", JAMMY_KERNEL) is None
    assert usn.release_na_reason(_linux(("xenial", "released", "weird")),
                                 "jammy", JAMMY_KERNEL) is None
    # only not-affected/DNE elsewhere, no fix to place: stay possible
    assert usn.release_na_reason(_linux(("xenial", "DNE", "")),
                                 "jammy", JAMMY_KERNEL) is None


def test_non_kernel_untracked_release_keeps_possible():
    data = {"packages": [{"name": "php7.0", "statuses": [
        {"release_codename": "xenial", "status": "released",
         "description": "7.0.33-0ubuntu0.16.04.1"}]}]}
    assert usn.release_na_reason(data, "jammy", {"php7.0": "7.0.1"}) is None


def test_not_installed_or_no_data_keeps_possible():
    assert usn.release_na_reason(_OLD_FIXED, "jammy", {}) is None
    assert usn.release_na_reason(None, "jammy", JAMMY_KERNEL) is None
    assert usn.release_na_reason(usn.NOT_TRACKED, "jammy", JAMMY_KERNEL) is None


def test_this_release_tracked_but_needed_is_never_downgraded():
    data = _linux(("xenial", "released", "4.4.0-45.66"), ("jammy", "needed", ""))
    assert usn.classify_cve(data, "jammy", JAMMY_KERNEL) == "applicable"
    assert usn.release_na_reason(data, "jammy", JAMMY_KERNEL) is None


# --- wiring through trends ------------------------------------------------- #
def _hits(n):
    return [tr.KevEntry(cve=f"CVE-2016-{i}", vendor="linux", product="kernel",
                        name="x", date_added="2022-03-03", due_date="",
                        ransomware=False) for i in range(1, n + 1)]


def _host(monkeypatch, data_for):
    monkeypatch.setattr(usn, "host_codename", lambda: "jammy")
    monkeypatch.setattr(usn, "installed_source_versions", lambda: dict(JAMMY_KERNEL))
    monkeypatch.setattr(usn, "cache_state", lambda cve: "fresh")
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: data_for(cve))
    monkeypatch.setattr(usn, "cache_status", lambda: {})


def test_applicability_labels_and_reasons(monkeypatch):
    fixed_here = _linux(("jammy", "released", "5.15.0-100.110"))
    _host(monkeypatch, lambda cve: _OLD_FIXED if cve == "CVE-2016-1" else fixed_here)
    reasons: dict[str, str] = {}
    labels = tr._applicability(_hits(2), max_checks=10, budget_s=30, reasons=reasons)
    assert labels == {"CVE-2016-1": "na_release", "CVE-2016-2": "fixed"}
    assert list(reasons) == ["CVE-2016-1"]


def test_matching_trends_counts_na_release_separately(monkeypatch):
    hits = _hits(2)
    _host(monkeypatch, lambda cve: _OLD_FIXED if cve == "CVE-2016-1" else None)
    monkeypatch.setattr(usn, "cached_cve", lambda cve: None)
    monkeypatch.setattr(tr, "_load_catalog", lambda url=tr.KEV_URL: hits)
    d = tr.matching_trends(host_terms=["linux"])
    assert d["na_release_count"] == 1
    assert d["not_applicable_count"] == 0
    assert d["unchecked_count"] == 1
    m = {x["cve"]: x for x in d["matches"]}
    assert m["CVE-2016-1"]["applicability"] == "na_release"
    assert "xenial" in m["CVE-2016-1"]["applicability_reason"]


def test_html_puts_na_release_rows_in_collapsed_block():
    from kevward.engine import RunResult
    from kevward.reporting.html import render

    def row(cve, label, reason=None):
        m = {"cve": cve, "vendor": "linux", "product": "kernel", "name": "x",
             "date_added": "2022-03-03", "ransomware": False, "applicability": label}
        if reason:
            m["applicability_reason"] = reason
        return m

    t = {"matches": [row("CVE-2022-0185", "possible"),
                     row("CVE-2016-5195", "na_release", "fixed upstream before linux 5.15")],
         "match_count": 2, "catalog_size": 2, "version_aware": True,
         "na_release_count": 1}
    out = render(RunResult(host="h", generated_at="2026-11-12T00:00:00+00:00",
                           os="Linux", attackers={"trends": t}))
    assert "1 n/a for this release" in out
    assert "<details" in out and "n/a (release)" in out
    main, _, folded = out.partition("<details")
    assert "CVE-2022-0185" in main and "CVE-2016-5195" not in main
    assert "CVE-2016-5195" in folded
