# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#170: apply's apt-get is not killed at 600 s and failures say what to do."""

from __future__ import annotations

import io
import sys

from kevward.model import Finding, FindingKind, Severity
from kevward.plugins import _apt
from kevward.util import Cmd, run_stream

AUDIT_HALF = ("The following packages are only half configured, probably due to problems\n"
              "configuring them the first time.  The configuration should be retried using\n"
              "dpkg --configure <package> or the configure menu option in dselect:\n"
              " linux-image-5.15.0-204-generic Signed kernel image generic\n")


class _K(_apt.AptServicePlugin):
    name = "apt"
    packages = []


def _kernel_finding():
    return Finding(service="apt", kind=FindingKind.SECURITY_UPDATE, severity=Severity.HIGH,
                   title="linux-generic", ref="linux-generic", reboot_required=True)


def _patch(monkeypatch, stream_result, audit_out=""):
    seen = {}

    def fake_stream(args, timeout=None, env=None, prefix="", stream=None):
        seen.update(args=args, timeout=timeout, env=env)
        return stream_result

    monkeypatch.setattr(_apt, "is_root", lambda: True)
    monkeypatch.setattr(_apt, "have", lambda n: True)
    monkeypatch.setattr(_apt, "run_stream", fake_stream)
    monkeypatch.setattr(_apt, "run", lambda args, timeout=120: Cmd(0, audit_out, ""))
    return seen


def test_install_uses_configured_timeout_and_noninteractive(monkeypatch):
    seen = _patch(monkeypatch, Cmd(0, "done\n", ""))
    [r] = _K().apply([_kernel_finding()], dry_run=False)
    assert r.ok and r.changed
    assert seen["timeout"] == 3600            # not 600
    assert seen["env"] == {"DEBIAN_FRONTEND": "noninteractive"}
    assert "Dpkg::Options::=--force-confold" in seen["args"]
    assert seen["args"][-1] == "linux-generic"


def test_timeout_reports_dpkg_audit_and_no_reboot(monkeypatch):
    _patch(monkeypatch, Cmd(124, "Unpacking...\n", "timed out after 3600s"), AUDIT_HALF)
    [r] = _K().apply([_kernel_finding()], dry_run=False)
    assert not r.ok
    first = r.output.splitlines()[0]
    assert "timed out after 3600s" in first
    assert "sudo dpkg --configure -a" in first
    assert "do not reboot" in first


def test_failure_with_clean_audit(monkeypatch):
    _patch(monkeypatch, Cmd(100, "", "E: Could not get lock"), "")
    [r] = _K().apply([_kernel_finding()], dry_run=False)
    assert not r.ok
    assert r.output.splitlines()[0] == ("apt-get failed (exit 100); dpkg --audit is clean "
                                        "(no half-installed packages)")


def test_failure_summary_non_kernel():
    s = _apt.failure_summary(1, 3600, AUDIT_HALF, kernel=False)
    assert "(1)" in s and "do not reboot" not in s


def test_run_stream_echoes_and_times_out():
    buf = io.StringIO()
    r = run_stream([sys.executable, "-c", "print('a'); print('b')"], stream=buf, prefix="> ")
    assert r.ok and r.out == "a\nb\n" and buf.getvalue() == "> a\n> b\n"
    r = run_stream([sys.executable, "-c", "import time; print('x', flush=True); time.sleep(30)"],
                   timeout=1, stream=io.StringIO())
    assert r.rc == 124 and "x" in r.out
    assert run_stream(["/nonexistent-kevward"]).rc == 127
