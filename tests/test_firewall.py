"""Unit tests for the firewall blocklist logic.

These cover the safety-critical parts without needing nft or root:
the allowlist (self-block guard), candidate selection, and TTL parsing.
Runnable with pytest, or directly: ``python tests/test_firewall.py``.
"""

from __future__ import annotations

from kevward.firewall import (
    Allowlist,
    Candidate,
    parse_duration_days,
    select,
    ttl_seconds,
)


def test_allowlist_never_blocks_protected_ranges():
    allow = Allowlist.build()
    # loopback, RFC1918, CGNAT, link-local are always allowlisted
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.9.9",
               "100.64.0.1", "169.254.1.1", "::1"):
        assert allow.allows(ip), ip
    # an ordinary public IP is NOT allowlisted
    assert not allow.allows("203.0.113.9")


def test_admin_ip_is_allowlisted_so_no_self_block():
    allow = Allowlist.build(admin_ips={"203.0.113.9"})
    assert allow.allows("203.0.113.9")
    # a configured CIDR is honoured too
    allow2 = Allowlist.build(extra=["198.51.100.0/24"])
    assert allow2.allows("198.51.100.50")
    assert not allow2.allows("203.0.113.9")


def test_select_excludes_allowlisted_candidates():
    allow = Allowlist.build(admin_ips={"203.0.113.9"})
    cands = [
        Candidate("203.0.113.9", "admin", 100),   # must be dropped
        Candidate("10.0.0.5", "rfc1918", 100),     # must be dropped
        Candidate("45.134.48.7", "fail2ban", 100),  # kept
    ]
    kept = {c.ip for c in select(cands, allow)}
    assert kept == {"45.134.48.7"}


def test_unparseable_ip_is_treated_as_allowlisted():
    # fail safe: if we cannot parse it, we never block it
    allow = Allowlist.build()
    assert allow.allows("not-an-ip")


def test_parse_duration_days():
    assert parse_duration_days("14d") == 14
    assert parse_duration_days("14") == 14
    assert parse_duration_days("48h") == 2
    assert parse_duration_days("1440m") == 1
    assert parse_duration_days("86400s") == 1
    try:
        parse_duration_days("soon")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_ttl_seconds_has_a_floor():
    assert ttl_seconds(14) == 14 * 86400
    assert ttl_seconds(0) == 60  # never below 60s


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all firewall tests passed")
