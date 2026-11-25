# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The apk subsystem itself (Alpine, #2): every pending upgrade host-wide.

The Alpine counterpart of the ``apt`` plugin: catches the kernel, libraries
and base system as well as services. Security updates come from the Alpine
secdb (see ``_apk``). Nothing is detected on hosts without ``apk``.
"""

from __future__ import annotations

from ..model import Finding
from ..plugin import register
from ..util import have
from ._apk import ApkServicePlugin, change_findings, pending_upgrades


@register
class ApkPlugin(ApkServicePlugin):
    name = "apk"
    packages: list[str] = []  # special-cased: this plugin owns the host

    def detect(self) -> bool:
        return have("apk")

    def version(self) -> str | None:
        return None

    def check(self) -> list[Finding]:
        return change_findings(self.name, pending_upgrades())
