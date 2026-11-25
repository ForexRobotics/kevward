# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The common envelope of kevward's JSON output (#116).

Every JSON document kevward prints or writes carries ``schema_version``. Within
1.x, keys and enum values may be added; removing or renaming a key, or
changing its type, bumps ``schema_version``. See docs/json-schema.md.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

SCHEMA_VERSION = 1


def stamp(data: dict) -> dict:
    """``schema_version`` and ``kevward_version`` first, then ``data``."""
    from . import __version__

    return {"schema_version": SCHEMA_VERSION, "kevward_version": __version__, **data}


def findings_doc(findings, **extra) -> dict:
    """A list of findings as a document (``audit --json``, ``harden check
    --json``): host, time and the findings."""
    return stamp({"host": socket.gethostname(),
                  "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  **extra,
                  "findings": [f.to_dict() for f in findings]})
