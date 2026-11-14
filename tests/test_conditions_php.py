# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""PHP CVEs Ubuntu tracks under php7.x / php5 never match a php8.x host (#62)."""

from __future__ import annotations

from kevward.integrations import conditions as c


class _F(c.HostFacts):
    def __init__(self, branches):
        super().__init__()
        self._b = branches

    def php_branches(self):
        return self._b


def test_parse_php_branches():
    srcs = {"php8.2": "x", "php8.4": "x", "php-defaults": "x", "php5": "x", "phpmyadmin": "x"}
    assert c.parse_php_branches(srcs) == [(5, 0), (8, 2), (8, 4)]


def test_hokaku_php8_rules_out_fpm_and_cgi():
    f = _F([(8, 2), (8, 3), (8, 4)])
    got = c.evaluate(["CVE-2019-11043", "CVE-2012-1823"], f)
    assert "installed PHP 8.2, 8.3, 8.4" in got["CVE-2019-11043"]
    assert "7.4+ never affected" in got["CVE-2019-11043"]
    assert "CVE-2012-1823" in got


def test_old_branch_or_unknown_keeps_possible():
    assert c.evaluate(["CVE-2019-11043"], _F([(7, 3), (8, 1)])) == {}
    assert c.evaluate(["CVE-2019-11043"], _F([])) == {}
    assert c.evaluate(["CVE-2019-11043"], _F(None)) == {}
    assert "CVE-2012-1823" in c.evaluate(["CVE-2012-1823"], _F([(7, 3)]))
