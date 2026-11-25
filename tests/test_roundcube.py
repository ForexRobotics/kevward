# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#138: the Roundcube plugin (version read from iniset.php, no install needed)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import roundcube as rc

# The top of program/include/iniset.php in Roundcube 1.6.x.
INISET = """\
<?php
/*
 +-----------------------------------------------------------------------+
 | Roundcube Webmail IMAP Client                                         |
 +-----------------------------------------------------------------------+
*/

// application constants
define('RCMAIL_VERSION', '1.6.9');
define('RCMAIL_START', microtime(true));
"""


def test_parse_version():
    assert rc.parse_version(INISET) == "1.6.9"
    assert rc.parse_version('define("RCMAIL_VERSION", "1.7-beta");') == "1.7-beta"
    assert rc.parse_version("<?php // nothing here") is None
    assert rc.parse_version("") is None


def _install(root, name, text=INISET):
    f = root / name / "program" / "include" / "iniset.php"
    f.parent.mkdir(parents=True)
    f.write_text(text)
    return root / name


def test_find_installs(tmp_path):
    a = _install(tmp_path, "webmail")
    _install(tmp_path, "webmail/vendor/x")            # inside an install: not walked
    _install(tmp_path, "a/b/c/d/e/deep")               # deeper than the limit
    assert rc.find_installs([str(tmp_path), str(tmp_path / "missing")]) == [a]


def test_no_roundcube(monkeypatch, tmp_path):
    monkeypatch.setattr(rc, "_pkg_version", lambda p: None)
    p = rc.RoundcubePlugin()
    p.roots = [str(tmp_path)]
    assert p.detect() is False and p.supports_apply is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert p.kev_terms == ["roundcube"]


def test_tarball_install_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(rc, "_pkg_version", lambda p: None)
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade",
                        lambda: (_ for _ in ()).throw(AssertionError("apt not consulted")))
    _install(tmp_path, "webmail")
    p = rc.RoundcubePlugin()
    p.roots = [str(tmp_path)]
    assert p.detect() and p.version() == "1.6.9"
    fs = p.check()
    assert [(f.severity, f.current_version) for f in fs] == [(Severity.INFO, "1.6.9")]
    assert str(tmp_path / "webmail") in fs[0].title
