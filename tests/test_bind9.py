# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#132: the BIND9 plugin (``named-checkconf -p`` parsed as text)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import bind9 as bn
from kevward.util import Cmd

# `named-checkconf -p` on a stock Ubuntu install (trimmed).
STOCK = """\
options {
\tdirectory "/var/cache/bind";
\tlisten-on-v6 {
\t\t"any";
\t};
\tdnssec-validation auto;
};
zone "localhost" {
\ttype primary;
\tfile "/etc/bind/db.local";
};
"""


def _opts(body: str) -> str:
    return 'options {\n\tdirectory "/var/cache/bind";\n' + body + "};\n"


def test_stock_is_not_open():
    # Default recursion ACL is localnets; localhost.
    assert bn.open_resolvers(STOCK) == []


def test_open_resolver():
    assert bn.open_resolvers(_opts('\tallow-recursion {\n\t\t"any";\n\t};\n')) == ["options"]
    assert bn.open_resolvers(_opts("\tallow-query { any; };\n")) == ["options"]
    assert bn.open_resolvers(_opts("\tallow-query-cache { 0.0.0.0/0; };\n")) == ["options"]


def test_limited_or_off():
    assert bn.open_resolvers(_opts("\tallow-recursion { localnets; localhost; };\n")) == []
    # allow-recursion wins over a public allow-query (authoritative + local resolver).
    assert bn.open_resolvers(_opts("\tallow-query { any; };\n"
                                   "\tallow-recursion { 10.0.0.0/8; };\n")) == []
    assert bn.open_resolvers(_opts("\trecursion no;\n\tallow-query { any; };\n")) == []
    # Negations are not open; "any" after one still is.
    assert bn.open_resolvers(_opts("\tallow-recursion { ! 1.2.3.4; localnets; };\n")) == []
    assert bn.open_resolvers(_opts("\tallow-recursion { ! any; };\n")) == []
    assert bn.open_resolvers(_opts("\tallow-recursion { ! 1.2.3.4; any; };\n")) == ["options"]


def test_views():
    conf = _opts("\tallow-recursion { any; };\n") + (
        'view "internal" {\n\tmatch-clients { localnets; };\n};\n'
        'view "external" {\n\tmatch-clients { any; };\n\trecursion no;\n};\n'
    )
    assert bn.open_resolvers(conf) == ["view internal"]


def test_comments_ignored():
    assert bn.open_resolvers(_opts("\t// allow-recursion { any; };\n"
                                   "\t/* allow-query { any; }; */\n")) == []


def test_check(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade", lambda: [])
    monkeypatch.setattr(bn, "run", lambda *a, **k: Cmd(1, "", "named.conf: error"))
    assert bn.Bind9Plugin().check() == []
    monkeypatch.setattr(bn, "run", lambda *a, **k: Cmd(
        0, _opts("\tallow-recursion { any; };\n"), ""))
    fs = bn.Bind9Plugin().check()
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.MEDIUM, "BIND9 is an open resolver (options)")]


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = bn.Bind9Plugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (
        ["bind9"], "named.service", ["isc:bind"])
