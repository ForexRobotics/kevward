# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#116: the documented top-level JSON keys stay (docs/json-schema.md).
Removing one breaks clients within 1.x and must bump schema_version."""

from __future__ import annotations

import json

from kevward import audit as ad
from kevward import harden as hd
from kevward.engine import RunResult
from kevward.jsonout import SCHEMA_VERSION, findings_doc
from kevward.model import Finding, FindingKind, Severity
from kevward.reporting.data import report_data

RUN_RESULT_KEYS = {
    "schema_version", "kevward_version", "host", "generated_at", "os",
    "reboot_required", "reboot_pending", "reboot_packages", "reboot_kind",
    "reboot_scheduled", "reboot_schedule_state", "config_source", "config_error",
    "config_warnings", "services", "attackers", "audit", "audit_allowed_outbound",
    "audit_allowed_forced", "audit_recognised", "audit_rules", "apt_refresh",
}
FINDING_KEYS = {"service", "kind", "severity", "title", "detail", "current_version",
                "fixed_version", "cve", "reboot_required", "ref", "packages", "url",
                "origin"}
F = Finding(service="audit", kind=FindingKind.CONFIG, severity=Severity.HIGH, title="t")


def _rr():
    return RunResult(host="h", generated_at="2026-11-25T00:00:00+00:00", os="Linux")


def test_schema_version_is_1():
    assert SCHEMA_VERSION == 1


def test_run_result_keys():
    d = json.loads(_rr().to_json())
    assert RUN_RESULT_KEYS <= set(d) and d["schema_version"] == 1


def test_report_json_keys(tmp_path):
    d = report_data(_rr(), jobs_dir=tmp_path)
    assert RUN_RESULT_KEYS | {"summary", "last_apply", "apply_refused"} <= set(d)


def test_finding_keys():
    assert FINDING_KEYS <= set(F.to_dict())


def test_findings_doc():
    d = findings_doc([F])
    assert {"schema_version", "kevward_version", "host", "generated_at", "findings"} \
        <= set(d)
    assert FINDING_KEYS <= set(d["findings"][0])


def test_audit_json_is_a_document(monkeypatch, capsys):
    monkeypatch.setattr(ad, "audit", lambda *a, **k: [F])
    ad.run_cli(use_json=True)
    d = json.loads(capsys.readouterr().out)
    assert d["schema_version"] == 1 and d["findings"][0]["title"] == "t"
    assert "allowed_outbound_hits" in d


def test_harden_check_json_is_a_document(monkeypatch, capsys):
    monkeypatch.setattr(hd, "check", lambda: [F])
    hd.run_cli("check", mptcp_off=False, drop_ip_options=False, persist=False,
               yes=False, use_json=True)
    d = json.loads(capsys.readouterr().out)
    assert d["schema_version"] == 1 and len(d["findings"]) == 1
