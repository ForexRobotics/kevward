"""PostgreSQL server: apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class PostgresqlPlugin(AptServicePlugin):
    name = "postgresql"
    packages = ["postgresql", "postgresql-common"]
    service_unit = "postgresql.service"
    kev_terms = ["postgresql", "postgres"]
