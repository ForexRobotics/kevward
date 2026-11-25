# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""HAProxy (#1): apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class HaproxyPlugin(AptServicePlugin):
    name = "haproxy"
    packages = ["haproxy"]
    service_unit = "haproxy.service"
    kev_terms = ["haproxy"]
