# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Apache Tomcat: apt packages + security-update detection (apt-based).

Ubuntu ships tomcat9 on 22.04 and tomcat10 on 24.04. The unit is pinned to
tomcat10.service, the current LTS package.
"""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class TomcatPlugin(AptServicePlugin):
    name = "tomcat"
    packages = ["tomcat9", "tomcat10"]
    service_unit = "tomcat10.service"
    kev_terms = ["apache:tomcat"]
