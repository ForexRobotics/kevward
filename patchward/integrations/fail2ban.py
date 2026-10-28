"""Collect banned-IP telemetry from fail2ban.

Prefers `fail2ban-client` (authoritative current state); falls back to parsing
the fail2ban log for a historical view of bans over time.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ..util import have, is_root, run

_BAN_LINE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?\bBan\b\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)


def _jails() -> list[str]:
    res = run(["fail2ban-client", "status"], timeout=20)
    if not res.ok:
        return []
    m = re.search(r"Jail list:\s*(.+)", res.out)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def currently_banned() -> dict[str, list[str]]:
    """{jail: [ip, ...]} of IPs banned right now. Needs fail2ban-client + root."""
    out: dict[str, list[str]] = {}
    if not (have("fail2ban-client") and is_root()):
        return out
    for jail in _jails():
        res = run(["fail2ban-client", "status", jail], timeout=20)
        if not res.ok:
            continue
        m = re.search(r"Banned IP list:\s*(.*)", res.out)
        ips = m.group(1).split() if m else []
        out[jail] = ips
    return out


def historical_bans(log_glob: str = "/var/log/fail2ban.log*") -> Counter:
    """Count Ban events per IP across (possibly rotated) fail2ban logs."""
    counts: Counter = Counter()
    from glob import glob
    import gzip

    for path in sorted(glob(log_glob)):
        p = Path(path)
        try:
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", errors="ignore") as fh:  # type: ignore[operator]
                for line in fh:
                    m = _BAN_LINE.search(line)
                    if m:
                        counts[m.group("ip")] += 1
        except OSError:
            continue
    return counts


def collect() -> dict:
    """Aggregate fail2ban telemetry for the report layer."""
    live = currently_banned()
    hist = historical_bans()
    live_total = sum(len(v) for v in live.values())
    return {
        "available": have("fail2ban-client"),
        "live_by_jail": live,
        "live_total": live_total,
        "top_offenders": hist.most_common(50),
        "unique_ips": len(hist),
        "total_ban_events": sum(hist.values()),
    }
