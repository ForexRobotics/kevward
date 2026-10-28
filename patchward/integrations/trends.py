"""Recent attack-trend awareness.

Pulls CISA's Known Exploited Vulnerabilities (KEV) catalog — the authoritative
list of CVEs *observed being exploited in the wild* — and cross-references it
against software detected on this host. The point is to answer the operator's
real question: "of everything being actively attacked right now, does any of it
apply to me?"

Network access is required and entirely opt-in (``patchward trends`` or
``report --trends``). The feed URL is configurable; results are cached so an
offline/locked-down host can still use the last snapshot.

No credentials, no outbound host data: this only downloads a public catalog.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE = Path("/var/cache/patchward/kev.json")
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
    def from_raw(cls, d: dict) -> "KevEntry":
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
        req = urllib.request.Request(url, headers={"User-Agent": "patchward"})
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


def matching_trends(
    host_terms: list[str] | None = None,
    url: str = KEV_URL,
) -> dict:
    """Return KEV entries plausibly relevant to this host, plus summary stats.

    ``host_terms`` lets callers pass detected product names (e.g. from the
    service plugins). When omitted, a broad built-in keyword list is used.
    """
    catalog = _load_catalog(url)
    terms = [t.lower() for t in (host_terms or _HOST_KEYWORDS)]
    hits: list[KevEntry] = []
    for e in catalog:
        hay = f"{e.vendor} {e.product} {e.name}".lower()
        if any(t in hay for t in terms):
            hits.append(e)
    hits.sort(key=lambda e: e.date_added, reverse=True)
    return {
        "catalog_size": len(catalog),
        "cache_fresh": _cache_fresh(),
        "match_count": len(hits),
        "ransomware_linked": sum(1 for e in hits if e.ransomware),
        "matches": [e.__dict__ for e in hits[:100]],
    }
