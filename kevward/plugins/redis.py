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
