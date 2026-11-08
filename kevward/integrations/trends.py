# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Recent attack-trend awareness.

Pulls CISA's Known Exploited Vulnerabilities (KEV) catalog — the authoritative
list of CVEs *observed being exploited in the wild* — and cross-references it
against software detected on this host. The point is to answer the operator's
real question: "of everything being actively attacked right now, does any of it
apply to me?"

Network access is required and entirely opt-in (``kevward trends`` or
``report --trends``). The feed URL is configurable; results are cached so an
offline/locked-down host can still use the last snapshot.

No credentials, no outbound host data: this only downloads a public catalog.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE = Path("/var/cache/kevward/kev.json")
CACHE_TTL = 6 * 3600  # seconds


@dataclass
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool

    @classmethod
    def from_raw(cls, d: dict) -> KevEntry:
        return cls(
            cve=d.get("cveID", ""),
            vendor=(d.get("vendorProject") or "").lower(),
            product=(d.get("product") or "").lower(),
            name=d.get("vulnerabilityName", ""),
            date_added=d.get("dateAdded", ""),
            due_date=d.get("dueDate", ""),
            ransomware=(d.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
        )


def _load_catalog(url: str = KEV_URL, timeout: int = 30) -> list[KevEntry]:
    """Fetch the KEV catalog, falling back to cache on any network error."""
    raw: dict | None = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kevward"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = json.loads(resp.read().decode("utf-8"))
        try:
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            CACHE.write_text(json.dumps(raw))
        except OSError:
            pass
    except Exception:
        if CACHE.is_file():
            raw = json.loads(CACHE.read_text())
    if not raw:
        return []
    return [KevEntry.from_raw(v) for v in raw.get("vulnerabilities", [])]


def _cache_fresh() -> bool:
    try:
        return CACHE.is_file() and (time.time() - CACHE.stat().st_mtime) < CACHE_TTL
    except OSError:
        return False


# Keywords describing software this host may run, mapped to KEV vendor/product
# substrings. Extend freely — matching is deliberately broad, then surfaced for
# a human to judge rather than acted on automatically.
_HOST_KEYWORDS = [
    "nginx", "apache", "php", "openssh", "openssl", "wordpress", "node",
    "nodejs", "laravel", "linux", "ubuntu", "mysql", "mariadb", "postgres",
    "redis", "docker", "fortinet", "cisco", "citrix", "vmware",
]


def term_matches(term: str, vendor: str, product: str) -> bool:
    """Does a host term name this KEV entry's vendor/product?

    Terms match as whole words, so ``php`` no longer hits ThinkPHP, phpMyAdmin
    or PHPUnit. ``vendor:product`` pins both sides, e.g. ``apache:http server``
    matches Apache HTTP Server but not Oracle HTTP Server.
    """
    def word(t: str, hay: str) -> bool:
        t = t.strip().lower()
        return bool(t) and re.search(
            rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", hay.lower()) is not None

    if ":" in term:
        v, p = term.split(":", 1)
        return word(v, vendor) and word(p, product)
    return word(term, f"{vendor} {product}")


def _applicability(
    hits: list[KevEntry], max_checks: int, budget_s: float
) -> dict[str, str]:
    """Label each name-matched CVE 'applicable' / 'fixed' / 'possible' /
    'unchecked' using the version-aware USN layer.

    'possible' means the lookup *ran* and found no installed, release-matched
    package to judge; 'unchecked' means it could not run for that CVE (lookup
    failed, per-run cap or time budget reached). Previously both collapsed into
    'possible', so two hosts on the same kernel could disagree depending on how
    far a cold-cache run got before the budget expired (#61).

    To make results converge rather than depend on network speed:
    - CVEs with a fresh cache entry are classified first (zero network cost);
    - each fetch's timeout is capped by the remaining budget;
    - once the budget is spent, remaining CVEs fall back to any cached entry,
      however old, before being reported 'unchecked'.
    Fail-soft: an empty dict means the layer did not run at all."""
    from . import usn

    codename = usn.host_codename()
    installed = usn.installed_source_versions() if codename else {}
    if not (codename and installed):
        return {}
    labels: dict[str, str] = {}
    order = {"fresh": 0, "stale": 1, "none": 2}
    queue = sorted(hits, key=lambda e: order[usn.cache_state(e.cve)])  # stable
    deadline = time.monotonic() + budget_s
    fetched = 0
    for e in queue:
        left = deadline - time.monotonic()
        state = usn.cache_state(e.cve)
        if state == "fresh":
            data = usn.fetch_cve(e.cve)  # served from cache, no network
        elif left > 0.5 and fetched < max_checks:
            fetched += 1
            data = usn.fetch_cve(e.cve, timeout=min(8.0, left))
        else:
            data = usn.cached_cve(e.cve)
        labels[e.cve] = (
            "unchecked" if data is None
            else usn.classify_cve(data, codename, installed)
        )
    return labels


def matching_trends(
    host_terms: list[str] | None = None,
    url: str = KEV_URL,
    version_aware: bool = True,
    max_version_checks: int = 80,
    version_budget_s: float = 45.0,
) -> dict:
    """Return KEV entries plausibly relevant to this host, plus summary stats.

    ``host_terms`` lets callers pass detected product names (e.g. from the
    service plugins). When omitted, a broad built-in keyword list is used.

    When ``version_aware`` is set (default), each name-matched CVE is further
    cross-referenced against this host's installed versions via Ubuntu's
    per-CVE security data, labelling it 'applicable' (unpatched here), 'fixed',
    'possible' (looked up, nothing installed to judge) or 'unchecked' (lookup
    failed or budget reached). The pass is bounded by ``max_version_checks``
    and ``version_budget_s`` and fails soft to name-level labelling.
    """
    catalog = _load_catalog(url)
    terms = [t.lower() for t in (host_terms or _HOST_KEYWORDS)]
    hits: list[KevEntry] = []
    for e in catalog:
        # Match only on vendor/product, never the free-text vulnerability name:
        # a name like "...PHP Remote File Inclusion" for a Zimbra/Juniper CVE
        # would otherwise false-match a host that merely runs PHP.
        if any(term_matches(t, e.vendor, e.product) for t in terms):
            hits.append(e)
    hits.sort(key=lambda e: e.date_added, reverse=True)

    labels: dict[str, str] = {}
    if version_aware and hits:
        try:
            labels = _applicability(hits, max_version_checks, version_budget_s)
        except Exception:
            labels = {}  # never let the version layer break a report

    def _match_dict(e: KevEntry) -> dict:
        d = dict(e.__dict__)
        d["applicability"] = labels.get(e.cve, "possible")
        return d

    def _count(v: str) -> int:
        return sum(1 for x in labels.values() if x == v)

    return {
        "catalog_size": len(catalog),
        "cache_fresh": _cache_fresh(),
        "match_count": len(hits),
        "ransomware_linked": sum(1 for e in hits if e.ransomware),
        "version_aware": bool(labels),
        "applicable_count": _count("applicable"),
        "fixed_count": _count("fixed"),
        "unchecked_count": _count("unchecked"),
        "matches": [_match_dict(e) for e in hits[:100]],
    }
