# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#154: npm audit runs inside each project, and a failed audit is visible."""

from __future__ import annotations

import json

from kevward.model import Severity
from kevward.plugins import nodejs
from kevward.util import Cmd, run

AUDIT_OK = json.dumps({"auditReportVersion": 2, "vulnerabilities": {
    "axios": {"name": "axios", "severity": "high", "range": "<1.7.4"},
    "vite": {"name": "vite", "severity": "moderate", "range": "5.0.0 - 5.4.5"},
}, "metadata": {}})
AUDIT_ERR = json.dumps({"error": {
    "code": "ENOLOCK", "summary": "This command requires an existing lockfile."}})


def _proj(tmp_path):
    p = tmp_path / "hokaku_server"
    p.mkdir()
    (p / "package.json").write_text("{}")
    (p / "package-lock.json").write_text("{}")
    return p


def test_npm_audit_runs_in_the_project(monkeypatch, tmp_path):
    proj = _proj(tmp_path)
    seen = {}

    def fake_run(args, timeout=120, input_=None, cwd=None):
        seen.update(args=args, cwd=cwd)
        return Cmd(1, AUDIT_OK, "")  # npm audit exits 1 when it finds advisories

    monkeypatch.setattr(nodejs, "run", fake_run)
    monkeypatch.setattr(nodejs, "have", lambda n: True)
    fs = nodejs.NodejsPlugin()._npm_audit(proj)
    assert seen["cwd"] == proj and seen["args"][:2] == ["npm", "audit"]
    assert {f.title for f in fs} == {"axios: high severity advisory",
                                     "vite: moderate severity advisory"}
    assert next(f for f in fs if f.title.startswith("axios")).severity == Severity.HIGH
    assert all(f.service == "npm:hokaku_server" for f in fs)


def test_error_and_garbage_are_not_checked_not_clean(tmp_path):
    for text in (AUDIT_ERR, "npm ERR! network ENOTFOUND registry.npmjs.org", ""):
        fs = nodejs.npm_audit_findings(tmp_path, text)
        assert len(fs) == 1 and fs[0].severity == Severity.INFO
        assert "not checked" in fs[0].title
    detail = nodejs.npm_audit_findings(tmp_path, AUDIT_ERR)[0].detail
    assert "requires an existing lockfile" in detail


def test_clean_audit_has_no_findings(tmp_path):
    assert nodejs.npm_audit_findings(tmp_path, json.dumps({"vulnerabilities": {}})) == []


def test_run_honours_cwd(tmp_path):
    r = run(["pwd"], cwd=tmp_path)
    assert r.ok and r.out.strip() == str(tmp_path.resolve())
    bad = run(["pwd"], cwd=tmp_path / "missing")
    assert not bad.ok and "working directory" in bad.err
