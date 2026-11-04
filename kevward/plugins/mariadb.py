# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""MariaDB server: apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class MariadbPlugin(AptServicePlugin):
    name = "mariadb"
    packages = ["mariadb-server", "mariadb-server-core"]
    service_unit = "mariadb.service"
    kev_terms = ["mariadb"]
