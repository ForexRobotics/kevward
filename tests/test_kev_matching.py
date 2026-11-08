# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""KEV name matching: whole words, and vendor:product pinning (pure)."""

from __future__ import annotations

import pytest

from kevward.integrations.trends import term_matches


@pytest.mark.parametrize("vendor,product", [
    ("php group", "php"),
    ("php", "fastcgi process manager (fpm)"),
    ("php", "php"),
])
def test_php_matches_php_itself(vendor, product):
    assert term_matches("php", vendor, product)


@pytest.mark.parametrize("vendor,product", [
    ("thinkphp", "thinkphp"),
    ("thinkphp", "nonecms"),
    ("phpmyadmin", "phpmyadmin"),
    ("phpunit", "phpunit"),
])
def test_php_does_not_match_other_products_containing_php(vendor, product):
    assert not term_matches("php", vendor, product)


def test_apache_http_server_pinned_to_apache():
    assert term_matches("apache:http server", "apache", "http server")
    assert not term_matches(
        "apache:http server", "oracle",
        "http server and oracle weblogic server proxy plug-in")
    assert not term_matches("apache:http server", "apache", "tomcat")


def test_existing_terms_still_match():
    assert term_matches("linux", "linux", "kernel")
    assert term_matches("openssh", "openbsd", "openssh")
    assert term_matches("node.js", "npm package",
                        "system information library for node.js")
    assert term_matches("laravel", "laravel", "livewire")
    assert term_matches("postgresql", "postgresql", "postgresql")
    assert not term_matches("postgres", "postgresql", "postgresql")  # word only
    assert not term_matches("", "linux", "kernel")
