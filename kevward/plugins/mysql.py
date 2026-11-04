# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""MySQL server: apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class MysqlPlugin(AptServicePlugin):
    name = "mysql"
    packages = ["mysql-server", "mysql-server-core-8.0", "mysql-community-server"]
    service_unit = "mysql.service"
    kev_terms = ["mysql"]
