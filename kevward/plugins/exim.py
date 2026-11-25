# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Exim (#131): apt packages + security-update detection (apt-based)."""

from __future__ import annotations

from ..plugin import register
from ._apt import AptServicePlugin


@register
class EximPlugin(AptServicePlugin):
    name = "exim"
    packages = ["exim4", "exim4-base", "exim4-daemon-light", "exim4-daemon-heavy"]
    service_unit = "exim4.service"
    kev_terms = ["exim"]
