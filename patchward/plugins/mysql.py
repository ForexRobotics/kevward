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
