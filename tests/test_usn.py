# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for the version-aware KEV layer (#3) — the pure parts that need
no network, root, or dpkg: Debian version comparison and CVE applicability."""

from __future__ import annotations

from kevward.integrations import trends as tr
from kevward.integrations import usn


# --- Debian version ordering ------------------------------------------------ #
def test_deb_compare_basic_ordering():
    assert usn.deb_compare("1.0", "1.0") == 0
    assert usn.deb_compare("1.0", "1.1") < 0
    assert usn.deb_compare("1.0.1", "1.0") > 0
    assert usn.deb_compare("1.0-1", "1.0-2") < 0
    assert usn.deb_compare("1.0", "1.0-1") < 0  # no revision < revision


def test_deb_compare_tilde_sorts_before_release():
    assert usn.deb_compare("1.0~rc1", "1.0") < 0
    assert usn.deb_compare("1.0~rc1", "1.0~rc2") < 0
    assert usn.deb_compare("1.0~~", "1.0~") < 0


def test_deb_compare_numeric_not_lexical():
    # the real libsoup case: 0.9 must sort *before* 0.10
    assert usn.deb_compare("2.74.2-3ubuntu0.9", "2.74.2-3ubuntu0.10") < 0
    assert usn.deb_compare("5.15.0-202.213", "5.15.0-203.213") < 0
    assert usn.deb_compare("1.15.0-203.213", "1.15.0-202") > 0


def test_deb_compare_epoch_wins():
    assert usn.deb_compare("1:1.0", "2.0") > 0
    assert usn.deb_compare("2.0", "1:1.0") < 0


def test_version_lt():
    assert usn.version_lt("1.0", "2.0") is True
    assert usn.version_lt("2.0", "1.0") is False
    assert usn.version_lt("2.74.2-3ubuntu0.9", "2.74.2-3ubuntu0.10") is True


# --- CVE applicability ------------------------------------------------------ #
_CVE = {
    "packages": [
        {
            "name": "libsoup2.4",
            "statuses": [
                {"release_codename": "jammy", "status": "released",
                 "description": "2.74.2-3ubuntu0.10"},
            ],
        }
    ]
}


def test_classify_applicable_when_installed_is_older():
    assert usn.classify_cve(_CVE, "jammy", {"libsoup2.4": "2.74.2-3ubuntu0.9"}) == "applicable"


def test_classify_fixed_when_installed_is_at_or_after_fix():
    assert usn.classify_cve(_CVE, "jammy", {"libsoup2.4": "2.74.2-3ubuntu0.10"}) == "fixed"
    assert usn.classify_cve(_CVE, "jammy", {"libsoup2.4": "2.74.2-3ubuntu0.11"}) == "fixed"


def test_classify_possible_when_not_installed_or_no_release_or_no_data():
    assert usn.classify_cve(_CVE, "jammy", {}) == "possible"          # not installed
    assert usn.classify_cve(_CVE, "noble", {"libsoup2.4": "1"}) == "possible"  # no status
    assert usn.classify_cve(None, "jammy", {"libsoup2.4": "1"}) == "possible"  # no data


def test_classify_needed_status_is_applicable():
    cve = {"packages": [{"name": "linux",
                         "statuses": [{"release_codename": "jammy", "status": "needed"}]}]}
    assert usn.classify_cve(cve, "jammy", {"linux": "5.15.0-100.110"}) == "applicable"


def test_classify_not_affected_is_possible():
    cve = {"packages": [{"name": "linux",
                         "statuses": [{"release_codename": "jammy", "status": "not-affected"}]}]}
    assert usn.classify_cve(cve, "jammy", {"linux": "5.15.0-100.110"}) == "possible"


def test_status_for_accepts_release_key_alias():
    pkg = {"statuses": [{"release": "jammy", "status": "released", "description": "1.2"}]}
    assert usn._status_for(pkg, "jammy")["description"] == "1.2"


# --- trends integration: opt-out and fail-soft keep name-level behaviour ---- #
def _one_hit():
    return [tr.KevEntry(cve="CVE-2026-1", vendor="nginx", product="nginx",
                        name="x", date_added="2026-01-01", due_date="", ransomware=False)]


def test_matching_trends_version_aware_off(monkeypatch):
    monkeypatch.setattr(tr, "_load_catalog", lambda url=tr.KEV_URL: _one_hit())
    d = tr.matching_trends(host_terms=["nginx"], version_aware=False)
    assert d["version_aware"] is False
    assert d["match_count"] == 1
    assert d["matches"][0]["applicability"] == "possible"


def test_matching_trends_failsoft_without_codename(monkeypatch):
    # no codename -> version layer is skipped, labels stay 'possible' (no network)
    monkeypatch.setattr(tr, "_load_catalog", lambda url=tr.KEV_URL: _one_hit())
    monkeypatch.setattr(usn, "host_codename", lambda: "")
    d = tr.matching_trends(host_terms=["nginx"], version_aware=True)
    assert d["version_aware"] is False
    assert d["matches"][0]["applicability"] == "possible"


# --- #61: budget/lookup failure is 'unchecked', not 'possible' ---- #
def _hits(n):
    return [tr.KevEntry(cve=f"CVE-2026-{i}", vendor="linux", product="kernel",
                        name="x", date_added="2026-01-01", due_date="", ransomware=False)
            for i in range(1, n + 1)]


_FIXED = {"packages": [{"name": "linux", "statuses": [
    {"release_codename": "jammy", "status": "released",
     "description": "5.15.0-100.110"}]}]}


def _host(monkeypatch):
    monkeypatch.setattr(usn, "host_codename", lambda: "jammy")
    monkeypatch.setattr(usn, "installed_source_versions",
                        lambda: {"linux": "5.15.0-202.212"})


def test_lookup_failure_is_unchecked(monkeypatch):
    _host(monkeypatch)
    monkeypatch.setattr(usn, "cache_state", lambda cve: "none")
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: None)
    labels = tr._applicability(_hits(2), max_checks=10, budget_s=30)
    assert set(labels.values()) == {"unchecked"}


def test_cap_reached_uses_stale_cache_then_unchecked(monkeypatch):
    _host(monkeypatch)
    monkeypatch.setattr(usn, "cache_state", lambda cve: "none")
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: _FIXED)
    cached = {"CVE-2026-2": _FIXED}
    monkeypatch.setattr(usn, "cached_cve", lambda cve: cached.get(cve))
    labels = tr._applicability(_hits(3), max_checks=1, budget_s=30)
    assert labels == {"CVE-2026-1": "fixed",      # fetched
                      "CVE-2026-2": "fixed",      # cap hit -> stale cache
                      "CVE-2026-3": "unchecked"}  # cap hit, nothing cached


def test_budget_spent_does_not_masquerade_as_possible(monkeypatch):
    _host(monkeypatch)
    monkeypatch.setattr(usn, "cache_state", lambda cve: "none")
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: _FIXED)
    monkeypatch.setattr(usn, "cached_cve", lambda cve: None)
    labels = tr._applicability(_hits(3), max_checks=10, budget_s=0)
    assert "possible" not in labels.values()
    assert set(labels.values()) == {"unchecked"}


def test_fresh_cache_first_and_counts(monkeypatch):
    _host(monkeypatch)
    hits = _hits(3)
    fresh = {"CVE-2026-3"}
    monkeypatch.setattr(usn, "cache_state",
                        lambda cve: "fresh" if cve in fresh else "none")
    seen = []

    def fake_fetch(cve, timeout=8):
        seen.append(cve)
        return _FIXED

    monkeypatch.setattr(usn, "fetch_cve", fake_fetch)
    tr._applicability(hits, max_checks=10, budget_s=30)
    assert seen[0] == "CVE-2026-3"  # cached entry classified before network ones

    monkeypatch.setattr(tr, "_load_catalog", lambda url=tr.KEV_URL: hits)
    monkeypatch.setattr(usn, "fetch_cve",
                        lambda cve, timeout=8: _FIXED if cve in fresh else None)
    monkeypatch.setattr(usn, "cached_cve", lambda cve: None)
    d = tr.matching_trends(host_terms=["linux"])
    assert d["unchecked_count"] == 2 and d["fixed_count"] == 1


# --- 404 from ubuntu.com = "not tracked", cached, not a failed lookup ------- #
def _http_error(code):
    import urllib.error
    def boom(req, timeout=8):
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)
    return boom


def test_404_is_cached_as_not_tracked_and_classifies_possible(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(usn.urllib.request, "urlopen", _http_error(404))
    data = usn.fetch_cve("CVE-2018-20062")  # ThinkPHP: not in Ubuntu's tracker
    assert data == usn.NOT_TRACKED
    assert usn.cache_state("CVE-2018-20062") == "fresh"  # not re-fetched next run
    assert usn.classify_cve(data, "jammy", {"linux": "5.15.0-202.212"}) == "possible"


def test_server_error_is_still_a_failed_lookup(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(usn.urllib.request, "urlopen", _http_error(503))
    assert usn.fetch_cve("CVE-2026-1") is None
    assert usn.cache_state("CVE-2026-1") == "none"


def test_404_not_tracked_never_ends_up_unchecked(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(usn.urllib.request, "urlopen", _http_error(404))
    _host(monkeypatch)
    labels = tr._applicability(_hits(2), max_checks=10, budget_s=30)
    assert set(labels.values()) == {"possible"}


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            try:
                obj()
            except TypeError:
                pass  # needs the monkeypatch fixture
            else:
                print(f"ok  {name}")
    print("done")
