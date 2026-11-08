# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Laravel plugin: app discovery (incl. per-user copies under /home-like
roots), framework EOL findings, and composer audit targeting the app dir."""

from __future__ import annotations

import tempfile
from datetime import date
from pathlib import Path

from kevward.model import Severity
from kevward.plugins import _composer
from kevward.plugins.laravel import _find_laravel_apps, _major, framework_findings
from kevward.util import Cmd


def _mkapp(p: Path) -> Path:
    p.mkdir(parents=True)
    (p / "artisan").write_text("")
    (p / "composer.lock").write_text("{}")
    return p


def test_finds_copies_in_web_root_and_home():
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        web = _mkapp(t / "www/html/ktaka/develop/hokaku-app")
        home = _mkapp(t / "home/hyasui/develop/hokaku-app")
        found = _find_laravel_apps([str(t / "www"), str(t / "home")])
        assert set(found) == {web, home}


def test_skips_vendor_hidden_and_too_deep():
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        _mkapp(t / "vendor/pkg/app")
        _mkapp(t / ".cache/app")
        _mkapp(t / "a/b/c/d/e/f/app")  # deeper than the default limit
        ok = _mkapp(t / "a/app")
        assert _find_laravel_apps([str(t)]) == [ok]


def test_overlapping_roots_report_app_once():
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        app = _mkapp(t / "home/u/website/app")
        found = _find_laravel_apps([str(t / "home"), str(t / "home/u/website")])
        assert found == [app]


def test_major_parsing():
    assert _major("v11.57.0") == "11"
    assert _major("13.38.0") == "13"
    assert _major("dev-master") is None


def test_laravel_11_past_security_eol_is_medium():
    f = framework_findings("laravel", Path("/x/hokaku-app"), "v11.57.0",
                           today=date(2026, 11, 9))
    assert len(f) == 2
    assert f[0].severity == Severity.INFO
    assert f[1].severity == Severity.MEDIUM
    assert "past end of security fixes" in f[1].title
    assert "/x/hokaku-app" in f[1].detail


def test_laravel_12_near_eol_is_low():
    f = framework_findings("laravel", Path("/x/app"), "v12.40.0",
                           today=date(2026, 11, 9))
    assert [x.severity for x in f] == [Severity.INFO, Severity.LOW]


def test_unlisted_major_gets_no_eol_finding():
    f = framework_findings("laravel", Path("/x/fr-site2"), "v13.38.0",
                           today=date(2026, 11, 9))
    assert len(f) == 1


def test_composer_audit_targets_app_dir_without_plugins(monkeypatch=None):
    calls = []

    def fake_run(args, timeout=120, input_=None):
        calls.append(args)
        return Cmd(0, '{"advisories": {}}', "")

    orig_run, orig_have = _composer.run, _composer.have
    _composer.run, _composer.have = fake_run, lambda name: True
    try:
        with tempfile.TemporaryDirectory() as td:
            app = _mkapp(Path(td) / "app")
            assert _composer.composer_audit(app) == []
    finally:
        _composer.run, _composer.have = orig_run, orig_have
    args = calls[0]
    assert f"--working-dir={app}" in args
    assert "--no-plugins" in args and "--no-scripts" in args


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all laravel tests passed")
