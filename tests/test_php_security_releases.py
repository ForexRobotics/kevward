# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#169: PPA PHP security releases are classified as security updates."""

from __future__ import annotations

import json

from kevward.config import Config
from kevward.integrations import php_releases as pr
from kevward.model import FindingKind, Severity
from kevward.plugins import _apt

SURY = "LP-PPA-ondrej-php:22.04/jammy [amd64]"
CUR = "8.3.36-1+ubuntu22.04.1+deb.sury.org+1"
NEW = "8.3.37-2+ubuntu22.04.1+deb.sury.org+1"

PHPNET_83 = {
    "8.3.37": {"tags": ["security"], "date": "19 Nov 2026"},
    "8.3.36": {"tags": ["security"], "date": "21 Oct 2026"},
    "8.3.35": {"tags": [], "date": "23 Sep 2026"},
}


def _sim(pkgs, origin=SURY, cur=CUR, new=NEW):
    return "\n".join(f"Inst {p} [{cur}] ({new} {origin})" for p in pkgs)


def test_pure_helpers():
    assert pr.php_branch("php8.3-fpm") == "8.3"
    assert pr.php_branch("php8.3") == "8.3"
    assert pr.php_branch("libapache2-mod-php8.2") == "8.2"
    assert pr.php_branch("php-common") is None
    assert pr.php_branch("phpmyadmin") is None
    assert pr.upstream_version(NEW) == "8.3.37"
    assert pr.upstream_version("1:8.1.2-1ubuntu2.20") == "8.1.2"
    rel = pr.parse_releases(PHPNET_83, "8.3")
    assert rel == {"8.3.37": True, "8.3.36": True, "8.3.35": False}
    assert pr.security_releases_between(rel, "8.3.36", "8.3.37") == ["8.3.37"]
    assert pr.security_releases_between(rel, "8.3.34", "8.3.35") == []  # bugfix only
    assert pr.security_releases_between({"8.3.35": False, "8.3.34": False},
                                        "8.3.34", "8.3.35") == []
    assert pr.security_releases_between(rel, "8.3.37", "8.3.38") is None  # not listed yet
    assert pr.parse_releases(["not", "a", "dict"], "8.3") is None
    assert pr.parse_releases({"error": "Unknown version"}, "8.3") is None
    # A format without "tags" must not read as "no security releases".
    assert pr.parse_releases({"8.3.37": {"date": "19 Nov 2026"}}, "8.3") is None
    assert pr.announcement_url("8.3.37") == "https://www.php.net/releases/8_3_37.php"


def test_ppa_php_security_release_is_high_grouped_with_link():
    changes = _apt.parse_inst(_sim(["php8.3", "php8.3-fpm", "php8.3-cli"]))
    assert not any(c["security"] for c in changes)  # the old behaviour
    _apt.classify_changes(changes, [], True,
                          php_fetch=lambda b: pr.parse_releases(PHPNET_83, b))
    src = {c["pkg"]: "php8.3" for c in changes}
    [f] = _apt.group_findings(changes, "apt", src, "jammy")
    assert f.kind is FindingKind.SECURITY_UPDATE and f.severity is Severity.HIGH
    assert f.url == "https://www.php.net/releases/8_3_37.php"  # not Ubuntu notices
    assert "PHP 8.3.37 is a security release (php.net)" in f.detail
    assert f.origin == "LP-PPA-ondrej-php:22.04/jammy"
    assert f.packages == ["php8.3", "php8.3-fpm", "php8.3-cli"]
    assert f.to_dict()["origin"] == "LP-PPA-ondrej-php:22.04/jammy"


def test_php_net_unreachable_stays_low_and_says_unchecked():
    changes = _apt.parse_inst(_sim(["php8.3-fpm"]))
    _apt.classify_changes(changes, [], True, php_fetch=lambda b: None)
    [f] = _apt.group_findings(changes, "apt", {"php8.3-fpm": "php8.3"}, "jammy")
    assert f.severity is Severity.LOW and f.kind is FindingKind.MINOR_UPGRADE
    assert "security status unchecked" in f.detail


def test_bugfix_release_stays_minor_without_note():
    changes = _apt.parse_inst(_sim(["php8.3-fpm"], cur="8.3.34-1+deb.sury.org+1",
                                   new="8.3.35-1+deb.sury.org+1"))
    _apt.classify_changes(changes, [], True,
                          php_fetch=lambda b: {"8.3.35": False, "8.3.34": False})
    f = _apt.change_finding("apt", changes[0])
    assert f.severity is Severity.LOW and "unchecked" not in f.detail


def test_check_disabled_and_revision_only_updates_do_not_fetch():
    calls = []

    def fetch(b):
        calls.append(b)
        return None

    changes = _apt.parse_inst(_sim(["php8.3-fpm"]))
    _apt.classify_changes(changes, [], False, php_fetch=fetch)
    assert calls == [] and not changes[0]["security"]
    # Same upstream version, new packaging revision: nothing to look up.
    changes = _apt.parse_inst(_sim(["php8.3-fpm"], new="8.3.36-2+ubuntu22.04.1+deb.sury.org+1"))
    _apt.classify_changes(changes, [], True, php_fetch=fetch)
    assert calls == [] and "security_unchecked" not in changes[0]
    # Ubuntu -security PHP is already security; never looked up.
    changes = _apt.parse_inst(_sim(["php8.1-fpm"], origin="Ubuntu:22.04/jammy-security [amd64]",
                                   cur="8.1.2-1ubuntu2.20", new="8.1.2-1ubuntu2.21"))
    _apt.classify_changes(changes, [], True, php_fetch=fetch)
    assert calls == [] and changes[0]["security"]


def test_security_origins_opt_in():
    changes = _apt.parse_inst(_sim(["nginx"], origin="LP-PPA-ondrej-nginx:22.04/jammy [amd64]",
                                   cur="1.26.1-1", new="1.26.2-1"))
    _apt.classify_changes(changes, ["LP-PPA-ondrej-*"], False)
    f = _apt.change_finding("apt", changes[0])
    assert f.severity is Severity.HIGH
    assert "matches [apt] security_origins" in f.detail
    other = _apt.parse_inst(_sim(["foo"], origin="Docker:jammy [amd64]", cur="1", new="2"))
    _apt.classify_changes(other, ["LP-PPA-ondrej-*"], False)
    assert not other[0]["security"]


def test_origin_names():
    assert _apt.origin_names("Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64]") \
        == ["Ubuntu", "Ubuntu"]
    assert _apt.origin_names(SURY) == ["LP-PPA-ondrej-php"]


def test_fetch_caches_and_fails_soft(monkeypatch, tmp_path):
    monkeypatch.setattr(pr, "_cache_file", lambda b: tmp_path / f"php-{b}.json")
    pr.fetch_releases.cache_clear()

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(PHPNET_83).encode()

    monkeypatch.setattr(pr.urllib.request, "urlopen", lambda *a, **k: Resp())
    assert pr.fetch_releases("8.3")["8.3.37"] is True
    assert (tmp_path / "php-8.3.json").is_file()

    def boom(*a, **k):
        raise OSError("offline")

    monkeypatch.setattr(pr.urllib.request, "urlopen", boom)
    pr.fetch_releases.cache_clear()
    (tmp_path / "php-8.3.json").touch()
    import os
    os.utime(tmp_path / "php-8.3.json", (0, 0))  # stale cache, network down
    assert pr.fetch_releases("8.3")["8.3.37"] is True
    pr.fetch_releases.cache_clear()
    assert pr.fetch_releases("8.2") is None
    assert pr.fetch_releases("8.3; rm") is None
    pr.fetch_releases.cache_clear()


def test_config_apt_section(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[apt]\nsecurity_origins = ["LP-PPA-ondrej-php"]\n'
                 'php_release_check = false\ninstall_timeout_s = 60\n')
    cfg = Config.load(p)
    assert cfg.load_error is None
    assert cfg.apt.security_origins == ["LP-PPA-ondrej-php"]
    assert cfg.apt.php_release_check is False
    assert cfg.apt.install_timeout_s == 300  # clamped
    p.write_text("[apt]\ninstall_timeout_s = 0\n")
    assert Config.load(p).apt.install_timeout_s == 0
    p.write_text('[apt]\ninstall_timeout_s = "soon"\n')
    assert Config.load(p).load_error
