"""Lightweight attacker signal from auth logs (logwatch-style, no dependency).

If `logwatch` is installed we capture its summary; independently we parse
sshd auth failures directly so the report works even without logwatch.
"""

from __future__ import annotations

import gzip
import re
from collections import Counter
from glob import glob
from pathlib import Path

from ..util import have, run

_IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"
_FAILED = re.compile(rf"Failed password for .*? from {_IP}")
_INVALID = re.compile(rf"Invalid user \S+ from {_IP}")


def ssh_auth_failures(log_glob: str = "/var/log/auth.log*") -> Counter:
    counts: Counter = Counter()
    for path in sorted(glob(log_glob)):
        p = Path(path)
        try:
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", errors="ignore") as fh:  # type: ignore[operator]
                for line in fh:
                    m = _FAILED.search(line) or _INVALID.search(line)
                    if m:
                        counts[m.group(1)] += 1
        except OSError:
            continue
    return counts


def logwatch_summary() -> str | None:
    if not have("logwatch"):
        return None
    res = run(
        ["logwatch", "--range", "yesterday", "--service", "sshd", "--output", "stdout"],
        timeout=120,
    )
    return res.out if res.ok else None


def collect() -> dict:
    fails = ssh_auth_failures()
    return {
        "logwatch_available": have("logwatch"),
        "ssh_failed_logins": fails.most_common(50),
        "ssh_unique_sources": len(fails),
        "ssh_total_attempts": sum(fails.values()),
    }
