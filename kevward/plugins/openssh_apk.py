# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""OpenSSH on Alpine (#2): an apk service plugin.

The Alpine counterpart of the ``sshd`` plugin's package part: pending
security / minor upgrades of the OpenSSH packages, from ``_apk``. On apt hosts
it detects nothing (the ``sshd`` plugin covers them).
"""

from __future__ import annotations

from ..plugin import register
from ._apk import ApkServicePlugin


@register
class OpensshApkPlugin(ApkServicePlugin):
    name = "openssh-apk"
    packages = ["openssh", "openssh-server", "openssh-client", "openssh-server-common",
                "openssh-client-default", "openssh-sftp-server"]
    service_unit = "sshd"
    kev_terms = ["openssh"]
