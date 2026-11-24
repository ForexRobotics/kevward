# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""``report.json``: the report's content as data (#211).

Written beside report.html by ``kevward report`` and served by ssh-gate
``report.get`` with ``format: "data"``, so a console can chart a host's
findings, KEV matches and attack telemetry over time without parsing HTML.

It is ``RunResult.to_dict()`` (the same object ``report --json`` prints) plus
``schema_version`` and a ``summary`` whose numbers are computed exactly as the
HTML header shows them (apt rows deduplicated, audit indicators included).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..engine import RunResult
from .html import SEVERITIES, fw_drop_totals, severity_counts

#: Bumped only on removals/renames/type changes (#116): new keys keep it.
SCHEMA_VERSION = 1


def _kev(trends: dict) -> dict | None:
    if not trends:
        return None
    matches = trends.get("matches") or []
    return {
        "version_aware": bool(trends.get("version_aware")),
        "matches": int(trends.get("match_count") or 0),
        "applicable": int(trends.get("applicable_count") or 0),
        "unchecked": int(trends.get("unchecked_count") or 0),
        "fixed": int(trends.get("fixed_count") or 0),
        "na_config": int(trends.get("not_applicable_count") or 0),
        "na_release": int(trends.get("na_release_count") or 0),
        "ransomware_linked": int(trends.get("ransomware_linked") or 0),
        "applicable_cves": sorted({m["cve"] for m in matches
                                   if m.get("applicability") == "applicable" and m.get("cve")}),
        "unchecked_cves": sorted({m["cve"] for m in matches
                                  if m.get("applicability") == "unchecked" and m.get("cve")}),
    }


def _attack(att: dict) -> dict:
    f2b = att.get("fail2ban") or {}
    lw = att.get("logwatch") or {}
    drops = fw_drop_totals(att.get("firewall") or {})
    return {
        "fail2ban_bans_total": int(f2b.get("total_ban_events") or 0),
        "fail2ban_unique_ips": int(f2b.get("unique_ips") or 0),
        "fail2ban_banned_now": int(f2b.get("live_total") or 0),
        "ssh_failed_total": int(lw.get("ssh_total_attempts") or 0),
        "ssh_unique_sources": int(lw.get("ssh_unique_sources") or 0),
        "ssh_failed_24h": lw.get("ssh_attempts_24h"),
        "ssh_failed_7d": lw.get("ssh_attempts_7d"),
        "ssh_window": {"start": lw.get("ssh_window_start"), "end": lw.get("ssh_window_end")},
        # Counters reset when the ruleset is reloaded: "since" is that time
        # (epoch seconds), so a console can turn totals into per-day numbers.
        "fw_drops": None if drops is None else {**drops, "since": att.get("firewall_since")},
        # The previous report's numbers (#225); null on the first report.
        "previous": att.get("previous"),
        "ssh_failed_24h_change_pct": change_pct(lw.get("ssh_attempts_24h"),
                                                (att.get("previous") or {}).get("ssh_failed_24h")),
    }


def previous_attack(path: Path) -> dict | None:
    """The attack numbers of the previous report.json at ``path`` (read before
    it is replaced), for day-over-day comparison (#225). None if absent."""
    try:
        prev = json.loads(path.read_text(encoding="utf-8"))
        att = prev["summary"]["attack"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return {"generated_at": prev.get("generated_at"),
            "ssh_failed_24h": att.get("ssh_failed_24h"),
            "ssh_failed_total": att.get("ssh_failed_total"),
            "fail2ban_bans_total": att.get("fail2ban_bans_total")}


def change_pct(cur, prev) -> int | None:
    """Percent change, None when there is nothing to compare."""
    if cur is None or prev is None or not isinstance(prev, (int, float)) or prev <= 0:
        return None
    return round(100 * (cur - prev) / prev)


def summarize(result: RunResult) -> dict:
    """The numbers the HTML header shows, as data. Pure."""
    counts, hidden = severity_counts(result)
    att = result.attackers or {}
    return {
        "counts": {k: counts.get(k, 0) for k in SEVERITIES},
        "act_now": counts.get("critical", 0) + counts.get("high", 0),
        "apt_rows_deduplicated": hidden,
        "audit_indicators": None if result.audit is None else len(result.audit),
        "kev": _kev(att.get("trends") or {}),
        "attack": _attack(att),
    }


def report_data(result: RunResult, jobs_dir: Path | None = None) -> dict:
    from ..gate_apply import JOBS_DIR, last_apply

    return {"schema_version": SCHEMA_VERSION, **result.to_dict(),
            # The latest console apply (#240): the report reflects it when
            # generated_at is later than last_apply.finished.
            "last_apply": last_apply(jobs_dir or JOBS_DIR),
            "summary": summarize(result)}


def write_report_data(path: Path, result: RunResult) -> dict:
    """Write ``report.json`` atomically, world-readable like report.html (the
    read role and collectors read it without root). Returns the data."""
    data = report_data(result)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str) + "\n",
                   encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(path)
    return data
