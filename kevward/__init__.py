# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""kevward - defensive server hardening & patch automation for Ubuntu.

A plugin-based CLI that inspects running services, reports known
vulnerabilities and available security updates, optionally applies
security patches / minor version upgrades, and schedules reboots.

This is a *defensive* tool. It never touches remote hosts and contains
no offensive capability.
"""

import sys as _sys

# Never write .pyc into the installed package at run time (#228): truthgate
# watches the package directory for changes outside a maintenance window.
# pip byte-compiles on install, and self.update runs compileall afterwards.
_sys.dont_write_bytecode = True

__version__ = "0.22.0"
