# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Redis server: apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class RedisPlugin(AptServicePlugin):
    name = "redis"
    packages = ["redis-server", "redis-tools"]
    service_unit = "redis-server.service"
    kev_terms = ["redis"]
