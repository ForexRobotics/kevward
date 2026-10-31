"""Unit tests for the DNSBL cross-check (pure logic + fail-soft; no network)."""

from __future__ import annotations

import struct

from kevward import firewall as fw


def _resp(rcode: int, a_ips: list[str]) -> bytes:
    """Build a minimal DNS response: 1 question echoed, len(a_ips) A answers."""
    flags = 0x8000 | (rcode & 0x0F)  # QR=1
    hdr = struct.pack(">HHHHHH", 0x1234, flags, 1, len(a_ips), 0, 0)
    qname = b"\x01a\x00"  # a single-label question name "a"
    question = qname + struct.pack(">HH", 1, 1)
    answers = b""
    for ip in a_ips:
        rdata = bytes(int(x) for x in ip.split("."))
        answers += b"\xc0\x0c"  # name pointer to offset 12
        answers += struct.pack(">HHIH", 1, 1, 300, 4) + rdata
    return hdr + question + answers


def test_classify_malicious_codes():
    for code in ("127.0.0.2", "127.0.0.4", "127.0.0.7", "127.0.0.9"):
        rcode, ips = fw._dns_parse(_resp(0, [code]))
        assert fw.classify_dnsbl(rcode, ips) == "malicious", code


def test_classify_policy_pbl_is_weak_not_blocked():
    rcode, ips = fw._dns_parse(_resp(0, ["127.0.0.10"]))
    assert fw.classify_dnsbl(rcode, ips) == "policy"


def test_classify_nxdomain_is_clean():
    rcode, ips = fw._dns_parse(_resp(3, []))
    assert fw.classify_dnsbl(rcode, ips) == "clean"


def test_classify_blocked_resolver_is_unknown():
    # Spamhaus returns 127.255.255.x when the querying resolver is blocked.
    rcode, ips = fw._dns_parse(_resp(0, ["127.255.255.254"]))
    assert fw.classify_dnsbl(rcode, ips) == "unknown"


def test_classify_servfail_is_unknown():
    assert fw.classify_dnsbl(2, []) == "unknown"


def test_lookup_ipv6_is_unknown_not_crash():
    assert fw.dnsbl_lookup("2001:db8::1", zone="zen.spamhaus.org") == "unknown"


def test_lookup_fails_soft_on_unreachable_resolver():
    # 192.0.2.1 is TEST-NET-1 (RFC5737): guaranteed unroutable -> timeout -> unknown
    v = fw.dnsbl_lookup("185.244.235.133", zone="zen.spamhaus.org",
                        resolver="192.0.2.1", timeout=1.0)
    assert v == "unknown"


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all dnsbl tests passed")
