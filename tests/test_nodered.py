# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#140: the Node-RED plugin (settings.js read as text, never executed)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import nodered as nr

# The shape of the settings.js Node-RED 3.x/4.x writes on first run.
DEFAULT_SETTINGS = """\
module.exports = {
    flowFile: 'flows.json',
    /** To password protect the Node-RED editor and admin API, the following
     * property can be used. See https://nodered.org/docs/security.html
     */
    //adminAuth: {
    //    type: "credentials",
    //    users: [{
    //        username: "admin",
    //        password: "$2a$08$zZWtXTja0fB1pzD4sHCMyOCMYz2Z6dNbM6tl8sJogENOMcxWV9DN.",
    //        permissions: "*"
    //    }]
    //},
    uiPort: process.env.PORT || 1880,
    /** By default, the Node-RED UI accepts connections on all IPv4 interfaces.
     * To listen on all IPv6 addresses, set uiHost to "::",
     */
    //uiHost: "127.0.0.1",
    editorTheme: { projects: { enabled: false } },
}
"""


def _settings(**lines: str) -> str:
    body = "\n".join(f"    {k}: {v}," for k, v in lines.items())
    return "module.exports = {\n    flowFile: 'flows.json',\n" + body + "\n}\n"


def test_parse_version():
    assert nr.parse_version('{"name": "node-red", "version": "4.0.9"}') == "4.0.9"
    assert nr.parse_version("{}") is None
    assert nr.parse_version("not json") is None
    assert nr.parse_version('["4.0.9"]') is None


def test_strip_comments_keeps_strings():
    code = nr.strip_js_comments('a: "http://x/*y*/", // gone\n/* gone */b: 1')
    assert 'a: "http://x/*y*/",' in code and "gone" not in code and "b: 1" in code


def test_default_settings_is_exposed():
    assert not nr.has_admin_auth(DEFAULT_SETTINGS)
    assert nr.ui_host(DEFAULT_SETTINGS) is None
    assert nr.editor_exposed(DEFAULT_SETTINGS) == "all interfaces (no uiHost)"


def test_admin_auth_protects():
    s = _settings(adminAuth='{ type: "credentials", users: [] }')
    assert nr.has_admin_auth(s) and nr.editor_exposed(s) is None
    assert nr.has_admin_auth(_settings(adminAuth="require('./user-authentication')"))
    assert not nr.has_admin_auth(_settings(adminAuth="null"))
    assert not nr.has_admin_auth(_settings(httpAdminAuth="null"))


def test_ui_host():
    assert nr.editor_exposed(_settings(uiHost='"127.0.0.1"')) is None
    assert nr.editor_exposed(_settings(uiHost="'localhost'")) is None
    assert nr.editor_exposed(_settings(uiHost='"::1"')) is None
    assert nr.editor_exposed(_settings(uiHost='"0.0.0.0"')) == "0.0.0.0"
    assert nr.editor_exposed(_settings(uiHost='"::"')) == "::"
    assert nr.editor_exposed(_settings(uiHost='"192.168.1.10"')) == "192.168.1.10"
    # Not a literal: unknown, so no finding.
    assert nr.editor_exposed(_settings(uiHost="process.env.HOST")) is None


def test_disable_editor():
    assert nr.editor_exposed(_settings(disableEditor="true")) is None
    assert nr.editor_exposed(_settings(disableEditor="false")) is not None


def _point_at(monkeypatch, tmp_path):
    monkeypatch.setattr(nr, "GLOBAL_PACKAGES", [tmp_path / "g/node-red/package.json"])
    monkeypatch.setattr(nr, "SERVICE_UNITS", [tmp_path / "nodered.service"])
    monkeypatch.setattr(nr, "HOMES", [tmp_path / "home"])
    monkeypatch.setattr(nr.Path, "home", classmethod(lambda cls: tmp_path / "me"))


def test_nothing_installed(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path)
    p = nr.NodeRedPlugin()
    assert p.detect() is False
    assert p.version() is None
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None


def test_global_install_with_open_editor(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path)
    pkg = tmp_path / "g/node-red/package.json"
    pkg.parent.mkdir(parents=True)
    pkg.write_text('{"name": "node-red", "version": "4.0.9"}')
    user = tmp_path / "home/pi/.node-red"
    user.mkdir(parents=True)
    (user / "settings.js").write_text(DEFAULT_SETTINGS)

    p = nr.NodeRedPlugin()
    assert p.detect() and p.version() == "4.0.9" and p.supports_apply is False
    fs = p.check()
    assert [f.severity for f in fs] == [Severity.INFO, Severity.MEDIUM]
    assert "4.0.9" in fs[0].title and str(user / "settings.js") in fs[1].detail
    assert all(f.ref is None for f in fs)

    (user / "settings.js").write_text(_settings(uiHost='"127.0.0.1"'))
    assert [f.severity for f in p.check()] == [Severity.INFO]


def test_service_unit_only(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path)
    (tmp_path / "nodered.service").write_text("[Service]\nExecStart=/usr/bin/node-red\n")
    p = nr.NodeRedPlugin()
    assert p.detect() and p.version() is None
    assert [f.title for f in p.check()] == ["Node-RED (version unknown)"]
