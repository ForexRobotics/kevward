# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

import pytest

from kevward import engine
from kevward.plugins import _apt


@pytest.fixture(autouse=True)
def _fresh_apt_plan():
    """The apt plan is cached per run (#171); start every test without one."""
    _apt.reset_simulation()
    yield
    _apt.reset_simulation()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "host_state: let engine.run() read this machine's kevward state")


@pytest.fixture(autouse=True)
def _no_host_state(request, monkeypatch):
    """engine.run() must not read the machine's own kevward state (change log,
    fail2ban, sandbox, ...): run as root on a host where kevward ran, that
    changed results (#294). Tests of those findings call their functions."""
    if "host_state" not in request.keywords:
        monkeypatch.setattr(engine, "kevward_findings", lambda cfg, do_apply: ([], []))
