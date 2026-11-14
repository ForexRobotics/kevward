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


# --- #62: real Ubuntu data from hokaku (2026-11-14) that #74 left 'possible' --
def _S(*rows):
    return _linux(*rows)


HOKAKU_1114 = {
    # upstream row never updated ("needed"); every Ubuntu release settled.
    "CVE-2010-3904": _S(("jaunty", "not-affected", ""), ("dapper", "DNE", ""),
                        ("hardy", "not-affected", ""), ("karmic", "released", "2.6.31-22.67"),
                        ("lucid", "released", "2.6.32-25.45"),
                        ("maverick", "released", "2.6.35-22.35"), ("upstream", "needed", "")),
    "CVE-2013-2094": _S(("upstream", "released", "3.9~rc8"), ("lucid", "not-affected", ""),
                        ("precise", "released", "3.2.0-43.68"),
                        ("xenial", "not-affected", "4.2.0-16.19")),
    "CVE-2013-2596": _S(("upstream", "released", "3.9~rc8"),
                        ("trusty", "not-affected", "3.11.0-12.19"),
                        ("focal", "not-affected", "5.4.0-9.12")),
    # "ignored" (end of life) on lucid used to block it; upstream says 3.6.
    "CVE-2013-6282": _S(("lucid", "ignored", ""), ("precise", "not-affected", "arm only"),
                        ("upstream", "released", "3.6~rc6"),
                        ("zesty", "not-affected", "4.8.0-22.24")),
    "CVE-2014-0196": _S(("lucid", "released", "2.6.32-58.121"),
                        ("trusty", "released", "3.13.0-24.47"),
                        ("upstream", "released", "3.15~rc5")),
    "CVE-2016-5195": _S(("upstream", "released", "4.9~rc2"),
                        ("xenial", "released", "4.4.0-45.66"),
                        ("zesty", "not-affected", "4.8.0-26.28")),
    "CVE-2017-1000253": _S(("bionic", "not-affected", "4.13.0-16.19"),
                           ("upstream", "released", "4.1~rc1"),
                           ("trusty", "released", "3.13.0-57.95")),
}


def test_upstream_tag_series():
    assert usn._kernel_series("3.9~rc8") == (3, 9)
    assert usn._kernel_series("4.1~rc1") == (4, 1)
    assert usn._kernel_series("2.6.32-25.45") == (2, 6)


def test_hokaku_old_kernel_cves_are_na_release_on_jammy_and_noble():
    for codename, kern in (("jammy", JAMMY_KERNEL), ("noble", {"linux": "6.8.0-149.149"})):
        for cve, data in HOKAKU_1114.items():
            assert usn.classify_cve(data, codename, kern) == "possible", cve
            why = usn.release_na_reason(data, codename, kern)
            assert why, (codename, cve)
    why = usn.release_na_reason(HOKAKU_1114["CVE-2016-5195"], "jammy", JAMMY_KERNEL)
    assert why.startswith("fixed upstream in 4.9~rc2, before linux 5.15")
    why = usn.release_na_reason(HOKAKU_1114["CVE-2010-3904"], "jammy", JAMMY_KERNEL)
    assert "2.6.35-22.35" in why and "maverick" in why


def test_upstream_fix_in_this_or_newer_series_keeps_possible():
    d = _S(("upstream", "released", "5.15~rc3"), ("focal", "needed", ""))
    assert usn.release_na_reason(d, "jammy", JAMMY_KERNEL) is None
    d = _S(("upstream", "released", "6.1"), ("focal", "released", "5.4.0-1.1"))
    assert usn.release_na_reason(d, "jammy", JAMMY_KERNEL) is None


def test_upstream_needed_alone_never_rules_out():
    d = _S(("upstream", "needed", ""), ("focal", "needed", ""))
    assert usn.release_na_reason(d, "jammy", JAMMY_KERNEL) is None


def test_tracked_release_still_wins_over_upstream():
    # jammy itself tracked as needed -> never n/a, whatever upstream says.
    d = _S(("upstream", "released", "3.9~rc8"), ("jammy", "needed", ""))
    assert usn.release_na_reason(d, "jammy", JAMMY_KERNEL) is None


# --- #62: Apache CVE-2019-0211, real Ubuntu data from hokaku (2026-11-14) -----
_APACHE_0211 = {"packages": [{"name": "apache2", "statuses": [
    {"release_codename": "bionic", "status": "released", "description": "2.4.29-1ubuntu4.6"},
    {"release_codename": "upstream", "status": "needs-triage", "description": ""},
]}]}


def test_apache_0211_na_when_upstream_past_fix():
    for codename, ver in (("jammy", "2.4.52-1ubuntu4.27"), ("noble", "2.4.58-1ubuntu8.8")):
        inst = {"apache2": ver}
        assert usn.classify_cve(_APACHE_0211, codename, inst) == "possible"
        why = usn.release_na_reason(_APACHE_0211, codename, inst, "CVE-2019-0211")
        assert why and "2.4.39" in why and ver in why


def test_apache_0211_old_upstream_keeps_possible():
    inst = {"apache2": "2.4.38-3+deb10u1"}
    assert usn.release_na_reason(_APACHE_0211, "jammy", inst, "CVE-2019-0211") is None


def test_upstream_table_ignored_when_release_tracked_or_other_cve():
    tracked = {"packages": [{"name": "apache2", "statuses": [
        {"release_codename": "jammy", "status": "needed", "description": ""}]}]}
    inst = {"apache2": "2.4.52-1ubuntu4.27"}
    assert usn.release_na_reason(tracked, "jammy", inst, "CVE-2019-0211") is None
    assert usn.release_na_reason(_APACHE_0211, "jammy", inst, "CVE-2099-0001") is None
