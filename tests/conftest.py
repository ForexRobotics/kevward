# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

import pytest

from kevward.plugins import _apt


@pytest.fixture(autouse=True)
def _fresh_apt_plan():
    """The apt plan is cached per run (#171); start every test without one."""
    _apt.reset_simulation()
    yield
    _apt.reset_simulation()
