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
from concurrent.futures import ThreadPoolExecutor, wait
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


#: Concurrent Ubuntu CVE lookups per run (#66). Kernel CVE JSONs are large and
#: slow (~5s each); a few in parallel lets a cold host converge in one run.
DEFAULT_FETCH_WORKERS = 4


def _prefetch(cves: list[str], deadline: float, workers: int) -> dict[str, dict | None]:
    """Fetch ``cves`` from Ubuntu concurrently until ``deadline`` (monotonic).

    Each lookup's timeout is capped by the budget left when it starts, and a
    lookup that would start with under half a second left is skipped, so the
    whole pass ends within the budget (plus at most one in-flight timeout).
    Results not back by the deadline are simply absent. Fail-soft.
    """
    from . import usn

    def one(cve: str) -> tuple[str, dict | None, bool]:
        left = deadline - time.monotonic()
        if left <= 0.5:
            return cve, None, False
        return cve, usn.fetch_cve(cve, timeout=min(8.0, left)), True

    out: dict[str, dict | None] = {}
    if not cves:
        return out
    pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="kevward-usn")
    try:
        futs = [pool.submit(one, c) for c in cves]
        done, _ = wait(futs, timeout=max(0.0, deadline - time.monotonic()) + 0.5)
        for f in done:
            try:
                cve, data, ran = f.result()
            except Exception:
                continue
            if ran:
                out[cve] = data
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out


def _applicability(
    hits: list[KevEntry], max_checks: int, budget_s: float,
    reasons: dict[str, str] | None = None,
    workers: int = DEFAULT_FETCH_WORKERS,
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
    - uncached CVEs (up to ``max_checks``) are fetched ``workers`` at a time
      (#66), each fetch's timeout capped by the remaining budget;
    - once the budget is spent, remaining CVEs fall back to any cached entry,
      however old, before being reported 'unchecked'.
    A 'possible' CVE that Ubuntu's data shows cannot apply to this release
    becomes 'na_release' (#74), with the reason put in ``reasons`` when given.

    Fail-soft: an empty dict means the layer did not run at all."""
    from . import usn

    codename = usn.host_codename()
    installed = usn.installed_source_versions() if codename else {}
    if not (codename and installed):
        return {}
    labels: dict[str, str] = {}
    order = {"fresh": 0, "stale": 1, "none": 2}
    states = {e.cve: usn.cache_state(e.cve) for e in hits}
    queue = sorted(hits, key=lambda e: order[states[e.cve]])  # stable
    deadline = time.monotonic() + budget_s
    # Stale before never-cached (queue order), capped by max_checks.
    to_fetch = [e.cve for e in queue if states[e.cve] != "fresh"][:max(0, max_checks)]
    fetched = _prefetch(to_fetch, deadline, workers)
    for e in queue:
        if states[e.cve] == "fresh":
            data = usn.fetch_cve(e.cve)  # served from cache, no network
        elif fetched.get(e.cve) is not None:
            data = fetched[e.cve]
        else:
            data = usn.cached_cve(e.cve)
        if data is None:
            labels[e.cve] = "unchecked"
            continue
        label = usn.classify_cve(data, codename, installed)
        if label == "possible":
            why = usn.release_na_reason(data, codename, installed)
            if why:
                label = "na_release"
                if reasons is not None:
                    reasons[e.cve] = why
        labels[e.cve] = label
    return labels


def matching_trends(
    host_terms: list[str] | None = None,
    url: str = KEV_URL,
    version_aware: bool = True,
    max_version_checks: int = 80,
    version_budget_s: float = 45.0,
    fetch_workers: int = DEFAULT_FETCH_WORKERS,
) -> dict:
    """Return KEV entries plausibly relevant to this host, plus summary stats.

    ``host_terms`` lets callers pass detected product names (e.g. from the
    service plugins). When omitted, a broad built-in keyword list is used.

    When ``version_aware`` is set (default), each name-matched CVE is further
    cross-referenced against this host's installed versions via Ubuntu's
    per-CVE security data, labelling it 'applicable' (unpatched here), 'fixed',
    'possible' (looked up, nothing installed to judge), 'na_release' (Ubuntu's
    data rules it out for this release, #74) or 'unchecked' (lookup failed or
    budget reached). The pass is bounded by ``max_version_checks``
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
    release_na: dict[str, str] = {}
    cache: dict | None = None
    if version_aware and hits:
        try:
            labels = _applicability(hits, max_version_checks, version_budget_s,
                                    reasons=release_na, workers=fetch_workers)
        except Exception:
            labels = {}  # never let the version layer break a report
        if labels:
            try:
                from . import usn
                cache = usn.cache_status()
            except Exception:
                cache = None

    # Config-conditional rules (#86): a CVE that only applies under a host
    # configuration this host does not have is shown as not applicable, with
    # the reason. Never overrides 'fixed' or 'applicable' from version data.
    config_na: dict[str, str] = {}
    if hits:
        try:
            from . import conditions
            config_na = conditions.evaluate([e.cve for e in hits])
        except Exception:
            config_na = {}

    # Composer-ecosystem CVEs (#62): Ubuntu does not track these, so decide
    # them from the host's composer.lock files. Only replaces labels the USN
    # layer could not settle.
    version_aware_ran = bool(labels)
    composer_reason: dict[str, str] = {}
    if hits:
        try:
            from . import composer_rules
            decided = composer_rules.evaluate([e.cve for e in hits])
        except Exception:
            decided = {}
        for cve, (lab, why) in decided.items():
            if labels.get(cve, "possible") not in ("possible", "unchecked", "na_release"):
                continue
            if lab == "not_applicable":
                config_na.setdefault(cve, why)
            else:
                labels[cve] = lab
                composer_reason[cve] = why

    def _match_dict(e: KevEntry) -> dict:
        d = dict(e.__dict__)
        d["applicability"] = labels.get(e.cve, "possible")
        reason = config_na.get(e.cve)
        if reason and d["applicability"] in (
            "possible", "unchecked", "not_applicable", "na_release"
        ):
            d["applicability"] = "not_applicable"
            d["applicability_reason"] = reason
        elif d["applicability"] == "na_release" and e.cve in release_na:
            d["applicability_reason"] = release_na[e.cve]
        elif e.cve in composer_reason:
            d["applicability_reason"] = composer_reason[e.cve]
        return d

    def _count(v: str) -> int:
        return sum(1 for x in labels.values() if x == v)

    return {
        "catalog_size": len(catalog),
        "cache_fresh": _cache_fresh(),
        "match_count": len(hits),
        "ransomware_linked": sum(1 for e in hits if e.ransomware),
        "version_aware": version_aware_ran,
        "applicable_count": _count("applicable"),
        "fixed_count": _count("fixed"),
        "unchecked_count": _count("unchecked"),
        # Not counted in not_applicable_count (config): a separate number so a
        # reader can see how many rows Ubuntu's release data ruled out (#74).
        "na_release_count": sum(
            1 for e in hits
            if labels.get(e.cve) == "na_release" and e.cve not in config_na
        ),
        "not_applicable_count": sum(
            1 for e in hits
            if e.cve in config_na and labels.get(e.cve) not in ("fixed", "applicable")
        ),
        "cve_cache": cache,
        "matches": [_match_dict(e) for e in hits[:100]],
    }
