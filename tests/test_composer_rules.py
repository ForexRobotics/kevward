# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Composer-ecosystem KEV rows decided from composer.lock (#62). No network."""

from __future__ import annotations

import json

from kevward.integrations import composer_rules as cr
from kevward.integrations import trends as tr
from kevward.integrations import usn


def _lock(tmp_path, name, pkgs, dev=()):
    d = tmp_path / name
    d.mkdir(parents=True)
    (d / "composer.lock").write_text(json.dumps({
        "packages": [{"name": n, "version": v} for n, v in pkgs],
        "packages-dev": [{"name": n, "version": v} for n, v in dev],
    }))
    return d


def test_version_ranges():
    fw = cr.RULES["CVE-2018-15133"]
    assert cr.is_vulnerable("v5.5.40", fw) and cr.is_vulnerable("v5.6.29", fw)
    assert not cr.is_vulnerable("v5.5.41", fw) and not cr.is_vulnerable("v5.6.30", fw)
    assert not cr.is_vulnerable("v11.57.0", fw) and not cr.is_vulnerable("v13.38.0", fw)
    lw = cr.RULES["CVE-2025-54068"]
    assert not cr.is_vulnerable("v2.12.6", lw)  # v2 not affected
    assert cr.is_vulnerable("v3.6.3", lw) and not cr.is_vulnerable("v3.6.4", lw)
    assert cr.is_vulnerable("dev-main", lw)  # unparseable -> never guessed safe


def test_hokaku_like_host(tmp_path):
    # laravel 11 app with spatie ignition (dev) and no livewire; fr-site2 on 13.
    _lock(tmp_path, "hokaku_server", [("laravel/framework", "v11.57.0")],
          dev=[("spatie/laravel-ignition", "2.9.1")])
    _lock(tmp_path, "fr-site2", [("laravel/framework", "v13.38.0")])
    got = cr.evaluate(["CVE-2018-15133", "CVE-2021-3129", "CVE-2025-54068", "CVE-2099-1"],
                      roots=[str(tmp_path)])
    assert got["CVE-2018-15133"][0] == "fixed"
    assert "v11.57.0" in got["CVE-2018-15133"][1] and "v13.38.0" in got["CVE-2018-15133"][1]
    assert got["CVE-2021-3129"][0] == "not_applicable"   # facade/ignition absent
    assert got["CVE-2025-54068"][0] == "not_applicable"  # no livewire
    assert "CVE-2099-1" not in got


def test_one_vulnerable_copy_makes_it_applicable(tmp_path):
    _lock(tmp_path, "new", [("livewire/livewire", "v3.6.4")])
    _lock(tmp_path, "old-backup", [("livewire/livewire", "v3.5.0")])
    lab, why = cr.evaluate(["CVE-2025-54068"], roots=[str(tmp_path)])["CVE-2025-54068"]
    assert lab == "applicable" and "old-backup" in why and "new:" not in why


def test_dev_dependency_counts(tmp_path):
    _lock(tmp_path, "app", [], dev=[("facade/ignition", "2.5.1")])
    assert cr.evaluate(["CVE-2021-3129"], roots=[str(tmp_path)])["CVE-2021-3129"][0] == "applicable"


def test_no_lock_files_or_unreadable_decides_nothing(tmp_path):
    assert cr.evaluate(["CVE-2021-3129"], roots=[str(tmp_path)]) == {}
    d = tmp_path / "broken"
    d.mkdir()
    (d / "composer.lock").write_text("{not json")
    _lock(tmp_path, "ok", [("laravel/framework", "v11.0.0")])
    assert cr.evaluate(["CVE-2021-3129"], roots=[str(tmp_path)]) == {}


def test_vendor_and_hidden_dirs_are_skipped(tmp_path):
    _lock(tmp_path, "app/vendor/x", [("facade/ignition", "2.0.0")])
    _lock(tmp_path, ".git/y", [("facade/ignition", "2.0.0")])
    _lock(tmp_path, "app2", [("laravel/framework", "v11.0.0")])
    assert cr.find_lock_files([str(tmp_path)]) == [tmp_path / "app2" / "composer.lock"]


def test_matching_trends_applies_composer_labels(monkeypatch):
    hits = [tr.KevEntry("CVE-2021-3129", "laravel", "ignition", "", "2021-11-18", "", False),
            tr.KevEntry("CVE-2018-15133", "laravel", "laravel framework", "",
                        "2022-01-18", "", False),
            tr.KevEntry("CVE-2016-5195", "linux", "kernel", "", "2022-03-03", "", False)]
    monkeypatch.setattr(tr, "_load_catalog", lambda url=tr.KEV_URL: hits)
    monkeypatch.setattr(usn, "host_codename", lambda: "jammy")
    monkeypatch.setattr(usn, "installed_source_versions", lambda: {"linux": "5.15.0-1"})
    monkeypatch.setattr(usn, "cache_state", lambda cve: "fresh")
    monkeypatch.setattr(usn, "fetch_cve", lambda cve, timeout=8: {"packages": []})
    monkeypatch.setattr(usn, "cache_status", lambda: {})
    monkeypatch.setattr(cr, "evaluate", lambda cves, roots=None: {
        "CVE-2021-3129": ("not_applicable", "facade/ignition is not in any composer.lock"),
        "CVE-2018-15133": ("fixed", "laravel/framework past the fix"),
    })
    d = tr.matching_trends(host_terms=["laravel", "linux"])
    m = {x["cve"]: x for x in d["matches"]}
    assert m["CVE-2021-3129"]["applicability"] == "not_applicable"
    assert m["CVE-2018-15133"]["applicability"] == "fixed"
    assert m["CVE-2018-15133"]["applicability_reason"] == "laravel/framework past the fix"
    assert m["CVE-2016-5195"]["applicability"] == "possible"
    assert d["fixed_count"] == 1 and d["not_applicable_count"] == 1
    assert d["version_aware"] is True


# --- PHPMailer (WordPress guard) and npm systeminformation -------------------
def _npm(tmp_path, name, pkgs, v2=True):
    d = tmp_path / name
    d.mkdir(parents=True)
    if v2:
        body = {"lockfileVersion": 3, "packages": {
            "": {"name": name}, **{f"node_modules/{n}": {"version": v} for n, v in pkgs}}}
    else:
        body = {"lockfileVersion": 1, "dependencies": {n: {"version": v} for n, v in pkgs}}
    (d / "package-lock.json").write_text(json.dumps(body))
    return d


def test_phpmailer_absent_is_na_unless_wordpress_present(tmp_path):
    _lock(tmp_path, "app", [("laravel/framework", "v11.0.0")])
    got = cr.evaluate(["CVE-2016-10033"], roots=[str(tmp_path)])
    assert got["CVE-2016-10033"][0] == "not_applicable"
    (tmp_path / "blog" / "wp-includes").mkdir(parents=True)
    assert cr.evaluate(["CVE-2016-10033"], roots=[str(tmp_path)]) == {}


def test_phpmailer_versions(tmp_path):
    _lock(tmp_path, "app", [("phpmailer/phpmailer", "v6.9.1")])
    assert cr.evaluate(["CVE-2016-10033"], roots=[str(tmp_path)])["CVE-2016-10033"][0] == "fixed"


def test_systeminformation_from_package_locks(tmp_path):
    _npm(tmp_path, "hokaku_server", [("vite", "5.4.0")])
    _npm(tmp_path, "old", [("axios", "1.0.0")], v2=False)
    got = cr.evaluate(["CVE-2021-21315"], roots=[str(tmp_path)], npm_global=[])
    assert got["CVE-2021-21315"][0] == "not_applicable"
    assert "package-lock.json" in got["CVE-2021-21315"][1]
    _npm(tmp_path, "tool", [("systeminformation", "5.2.0")], v2=False)
    assert cr.evaluate(["CVE-2021-21315"], roots=[str(tmp_path)],
                       npm_global=[])["CVE-2021-21315"][0] == "applicable"


def test_systeminformation_global_install(tmp_path):
    _npm(tmp_path / "www", "app", [("vite", "5.4.0")])
    g = tmp_path / "global"
    (g / "systeminformation").mkdir(parents=True)
    (g / "systeminformation" / "package.json").write_text(
        json.dumps({"name": "systeminformation", "version": "5.21.7"}))
    got = cr.evaluate(["CVE-2021-21315"], roots=[str(tmp_path / "www")], npm_global=[str(g)])
    assert got["CVE-2021-21315"][0] == "fixed" and "5.21.7" in got["CVE-2021-21315"][1]


def test_node_modules_without_lock_blocks_na(tmp_path):
    _npm(tmp_path, "app", [("vite", "5.4.0")])
    (tmp_path / "loose" / "node_modules").mkdir(parents=True)
    assert cr.evaluate(["CVE-2021-21315"], roots=[str(tmp_path)], npm_global=[]) == {}
