# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#139: the phpMyAdmin plugin (versions and web config read as text)."""

from __future__ import annotations

from pathlib import Path

from kevward.model import Severity
from kevward.plugins import phpmyadmin as pma

VERSION_5 = """\
<?php
declare(strict_types=1);
namespace PhpMyAdmin;
final class Version
{
    // The VERSION_SUFFIX constant is defined at libraries/constants.php
    public const VERSION = '5.2.1' . VERSION_SUFFIX;
    public const SERIES = '5.2';
    public const MAJOR = 5;
}
"""
CONFIG_4 = "<?php\n        $this->set('PMA_VERSION', '4.9.5deb2');\n"

# /etc/apache2/conf-enabled/phpmyadmin.conf from the Ubuntu package (trimmed).
APACHE_CONF = """\
# phpMyAdmin default Apache configuration

Alias /phpmyadmin /usr/share/phpmyadmin

<Directory /usr/share/phpmyadmin>
    Options SymLinksIfOwnerMatch
</Directory>
"""


def test_parse_version():
    assert pma.parse_version(VERSION_5) == "5.2.1"
    assert pma.parse_version(CONFIG_4) == "4.9.5deb2"
    assert pma.parse_version("public const VERSION = '6.0.0-dev';") == "6.0.0-dev"
    assert pma.parse_version("<?php echo 1;") is None


def test_web_aliases():
    assert pma.web_aliases(APACHE_CONF) == ["Alias /phpmyadmin /usr/share/phpmyadmin"]
    assert pma.web_aliases("#Alias /phpmyadmin /usr/share/phpmyadmin\n") == []
    nginx = "server {\n  location /phpMyAdmin {\n    root /usr/share/;\n  }\n}\n"
    assert pma.web_aliases(nginx) == ["location /phpMyAdmin {"]
    assert pma.web_aliases("Alias /mail /usr/share/roundcube\n") == []


def _install(root: Path, rel: str, vfile: str = "libraries/classes/Version.php",
             text: str = VERSION_5) -> Path:
    f = root / rel / vfile
    f.parent.mkdir(parents=True)
    f.write_text(text)
    return root / rel


def _plugin(monkeypatch, tmp_path):
    monkeypatch.setattr(pma, "_pkg_version", lambda p: None)
    conf = tmp_path / "apache"
    conf.mkdir(exist_ok=True)
    monkeypatch.setattr(pma, "WEB_CONFIG_DIRS", [conf])
    p = pma.PhpMyAdminPlugin()
    p.roots = [str(tmp_path / "www")]
    p.apt_dir = tmp_path / "usr-share-phpmyadmin"
    return p


def test_nothing_installed(monkeypatch, tmp_path):
    p = _plugin(monkeypatch, tmp_path)
    assert p.detect() is False and p.supports_apply is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert p.kev_terms == ["phpmyadmin"]


def test_tarball_under_web_root(monkeypatch, tmp_path):
    p = _plugin(monkeypatch, tmp_path)
    _install(tmp_path / "www", "html/pma", "libraries/Config.php", CONFIG_4)
    assert p.detect() and p.version() == "4.9.5deb2"
    fs = p.check()
    assert [f.severity for f in fs] == [Severity.INFO, Severity.LOW]
    assert "html/pma" in fs[1].detail


def test_apt_install_only_exposed_when_aliased(monkeypatch, tmp_path):
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade", lambda: [])
    p = _plugin(monkeypatch, tmp_path)
    _install(tmp_path, "usr-share-phpmyadmin")
    assert [f.severity for f in p.check()] == [Severity.INFO]

    (tmp_path / "apache" / "phpmyadmin.conf").write_text(APACHE_CONF)
    fs = p.check()
    assert [f.severity for f in fs] == [Severity.INFO, Severity.LOW]
    assert "Alias /phpmyadmin" in fs[1].detail
