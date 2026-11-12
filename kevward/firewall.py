# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Active-defense blocklist: a kevward-owned nftables set of high-confidence
attacker IPs, built from the host's *own* fail2ban / sshd evidence.

Strictly local-host only. This filters **ingress on the host kevward runs on**.
It never contacts, scans, or acts on any remote system -- this is active
defense on your own infrastructure, not hack-back (see AGENTS.md).

Safety model (issue #4):
- nftables native set only, in kevward's own table/chain/set. No-op if nft is
  absent; never touches rules kevward did not create.
- A mandatory allowlist always wins: loopback, RFC1918, CGNAT, link-local, the
  current admin/SSH source(s), and any configured CIDRs are never blocked, so
  it is impossible to self-block via the default flow.
- Dry-run by default (`plan`); `apply` commits. Every element carries a TTL, so
  the set ages out instead of growing forever.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

from .integrations import fail2ban, logwatch
from .util import have, is_root, run, which

# kevward-owned nftables objects. We only ever touch these.
TABLE = "kevward"
SET4 = "blocklist4"            # evidence-based host IPs, TTL'd
SET6 = "blocklist6"
ALLOW4 = "allow4"             # accept set: the allowlist wins at nft level too
ALLOW6 = "allow6"
BLOCKCIDR4 = "blockcidr4"     # operator-configured permanent blocks (CIDR/IP)
BLOCKCIDR6 = "blockcidr6"
CHAIN = "input"

# Reboot-persistence (issue #12): a kevward-owned systemd unit re-applies the
# saved ruleset on boot, exactly like kevward-harden does for harden.
PERSIST_FILE = "/etc/kevward/firewall.nft"
PERSIST_UNIT = "kevward-firewall.service"
PERSIST_UNIT_FILE = "/etc/systemd/system/kevward-firewall.service"
# Written (apply path only) whenever kevward's drop rules are (re)created, which
# resets their counters. Read by the report to say "since <when>".
COUNTERS_STAMP = "/var/lib/kevward/firewall-counters-reset"
_UNIT_TEMPLATE = """\
[Unit]
Description=kevward: reapply active-defense firewall blocklist on boot
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart={nft} -f {file}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""

# Networks that must NEVER be blocked (the hard allowlist floor).
_DEFAULT_ALLOW = [
    "127.0.0.0/8", "::1/128",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
    "100.64.0.0/10",                                   # CGNAT (RFC6598)
    "169.254.0.0/16", "fe80::/10",                     # link-local
    "fc00::/7",                                        # unique-local v6
]


# --------------------------------------------------------------------------- #
# Pure logic (unit-tested without nft or root)
# --------------------------------------------------------------------------- #
@dataclass
class Allowlist:
    """CIDRs that are never blocked. Parsing is forgiving; an unparseable
    candidate IP is treated as allowlisted (fail safe: never block)."""

    nets: list = field(default_factory=list)

    @classmethod
    def build(cls, extra: list[str] | None = None,
              admin_ips: set[str] | None = None) -> Allowlist:
        nets: list = []
        for cidr in _DEFAULT_ALLOW + list(extra or []):
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        for ip in admin_ips or set():
            try:
                nets.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                continue
        return cls(nets)

    def allows(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in self.nets)


@dataclass
class Candidate:
    ip: str
    reason: str
    score: int


def gather_candidates(min_sshd_failures: int = 20) -> list[Candidate]:
    """High-confidence attacker IPs from this host's own evidence.

    Strong: IPs fail2ban banned (now, or repeatedly in its logs).
    Medium: sshd auth failures at/above the threshold.
    Single stray failures never qualify.
    """
    cands: dict[str, Candidate] = {}

    fb = fail2ban.collect()
    for jail, ips in fb.get("live_by_jail", {}).items():
        for ip in ips:
            cands[ip] = Candidate(ip, f"fail2ban:{jail} (banned now)", 100)
    for ip, n in fb.get("top_offenders", []):
        if ip not in cands:
            cands[ip] = Candidate(ip, f"fail2ban ban events x{n}", 90)

    lw = logwatch.collect()
    for ip, n in lw.get("ssh_failed_logins", []):
        if n >= min_sshd_failures and ip not in cands:
            cands[ip] = Candidate(ip, f"sshd auth failures x{n}", min(80, int(n)))

    return list(cands.values())


def covered_by(ip: str, cidrs: list[str]) -> str | None:
    """The first permanent-block CIDR that already contains ``ip``, else None.

    Pure. An IP inside an operator ``blockcidr`` is already dropped, so adding
    it to the TTL'd evidence set too only clutters ``firewall list``.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return c
    return None


def select(candidates: list[Candidate], allow: Allowlist) -> list[Candidate]:
    """Candidates that are not allowlisted. This is the self-block guard."""
    return [c for c in candidates if not allow.allows(c.ip)]


def parse_duration_days(s: str) -> float:
    """'14d' / '72h' / '30m' / '3600s' / '14' (days) -> days (float)."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([dhms]?)\s*", s.lower())
    if not m:
        raise ValueError(f"bad duration: {s!r}")
    val = float(m.group(1))
    return {"": val, "d": val, "h": val / 24, "m": val / 1440, "s": val / 86400}[
        m.group(2)
    ]


def ttl_seconds(days: float) -> int:
    return max(60, int(days * 86400))


# --------------------------------------------------------------------------- #
# Host introspection (best-effort; never fatal)
# --------------------------------------------------------------------------- #
def session_admin_ips() -> set[str]:
    """IP(s) of the SSH session running kevward right now, from sshd's env.
    This is *definitely* the operator, so it is safe to allowlist even in the
    persisted accept set."""
    ips: set[str] = set()
    for var in ("SSH_CLIENT", "SSH_CONNECTION"):
        val = os.environ.get(var, "")
        if val:
            ips.add(val.split()[0])
    return ips


def current_admin_ips() -> set[str]:
    """session_admin_ips() plus established inbound SSH peers (best-effort).

    Used only for the in-memory self-block guard (``select``). NOT for the
    persisted accept set: an established :22 connection can be an attacker
    mid-brute-force, and persisting that as "allowed" would defeat the
    blocklist (issue #17). The accept set uses session_admin_ips() only."""
    ips = session_admin_ips()
    res = run(["ss", "-tn", "state", "established", "sport", "=", ":22"], timeout=10)
    if res.ok:
        for line in res.out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                host = parts[3].rsplit(":", 1)[0].strip("[]")
                if host:
                    ips.add(host)
    return ips


# --------------------------------------------------------------------------- #
# nftables backend (only ever touches kevward's own table)
# --------------------------------------------------------------------------- #
def _nft(args: list[str], input_: str | None = None):
    return run(["nft", *args], input_=input_)


def nft_available() -> bool:
    return have("nft")


def _table_snippet() -> str:
    """kevward's table. The allowlist is an *accept* set checked before the
    drops, so it wins even over an operator's permanent CIDR block. Evidence
    IPs are TTL'd (``blocklist*``); operator blocks are permanent CIDR/IP sets
    (``blockcidr*``, interval + auto-merge so overlapping ranges just merge)."""
    return (
        f"table inet {TABLE} {{\n"
        f"  set {ALLOW4} {{ type ipv4_addr; flags interval; auto-merge; }}\n"
        f"  set {ALLOW6} {{ type ipv6_addr; flags interval; auto-merge; }}\n"
        f"  set {SET4} {{ type ipv4_addr; flags timeout; }}\n"
        f"  set {SET6} {{ type ipv6_addr; flags timeout; }}\n"
        f"  set {BLOCKCIDR4} {{ type ipv4_addr; flags interval; auto-merge; }}\n"
        f"  set {BLOCKCIDR6} {{ type ipv6_addr; flags interval; auto-merge; }}\n"
        f"  chain {CHAIN} {{\n"
        f"    type filter hook input priority -150; policy accept;\n"
        f"    ip saddr @{ALLOW4} accept\n"
        f"    ip6 saddr @{ALLOW6} accept\n"
        f"    ip saddr @{SET4} counter drop\n"
        f"    ip6 saddr @{SET6} counter drop\n"
        f"    ip saddr @{BLOCKCIDR4} counter drop\n"
        f"    ip6 saddr @{BLOCKCIDR6} counter drop\n"
        f"  }}\n"
        f"}}\n"
    )


def _schema_current() -> bool:
    """True if the live table already uses the current schema (accept set +
    permanent-CIDR set). An older table (issue #4 schema) is recreated once so
    the new sets and the allow-accept rule exist; its elements are re-added by
    the same apply."""
    r = _nft(["list", "table", "inet", TABLE])
    return r.ok and ALLOW4 in r.out and BLOCKCIDR4 in r.out


def ensure_table() -> tuple[bool, str]:
    """Idempotently create kevward's table/sets/chain. Only our own objects are
    ever touched. An older-schema table is recreated once; otherwise only our
    chain's rules are reasserted and set contents are preserved."""
    if not nft_available():
        return False, "nftables (nft) not found"
    if not is_root():
        return False, "root required"
    exists = _nft(["list", "table", "inet", TABLE]).ok
    if exists and not _schema_current():
        _nft(["delete", "table", "inet", TABLE])
        exists = False
    if not exists:
        r = _nft(["-f", "-"], input_=_table_snippet())
        if not r.ok:
            return False, r.err.strip() or "nft create failed"
    else:
        # Reassert only our own chain's rules; leaves set contents intact.
        _nft(["flush", "chain", "inet", TABLE, CHAIN])
        for proto, setname, verdict in (
            ("ip", ALLOW4, "accept"), ("ip6", ALLOW6, "accept"),
            ("ip", SET4, "drop"), ("ip6", SET6, "drop"),
            ("ip", BLOCKCIDR4, "drop"), ("ip6", BLOCKCIDR6, "drop"),
        ):
            # counter on the drops so `nft list` / `firewall list` shows how
            # much each block set is actually catching.
            extra = ["counter"] if verdict == "drop" else []
            _nft(["add", "rule", "inet", TABLE, CHAIN, proto, "saddr",
                  f"@{setname}", *extra, verdict])
    # Both paths above recreate the counted drop rules, so their counters now
    # start from zero. Record when, so the report can say "since <when>".
    _stamp_counter_reset()
    return True, "ok"


def _stamp_counter_reset() -> None:
    """Best-effort: record the time the drop counters were reset."""
    try:
        os.makedirs(os.path.dirname(COUNTERS_STAMP), exist_ok=True)
        with open(COUNTERS_STAMP, "w") as fh:
            fh.write(f"{int(time.time())}\n")
    except OSError:
        pass


def _set_elements(setname: str) -> set[str]:
    out: set[str] = set()
    r = _nft(["list", "set", "inet", TABLE, setname])
    if not r.ok:
        return out
    m = re.search(r"elements\s*=\s*\{(.*?)\}", r.out, re.S)
    if not m:
        return out
    for tok in m.group(1).split(","):
        tok = tok.strip()
        if tok:
            out.add(tok.split()[0])
    return out


def current_set_ips() -> set[str]:
    """Evidence-based host IPs currently in the TTL'd blocklist (for dedup)."""
    return _set_elements(SET4) | _set_elements(SET6)


# Matches a counted drop rule in an `nft list table inet kevward` dump, e.g.
#   ip saddr @blocklist4 counter packets 1747 bytes 104252 drop
_DROP_COUNTER_RE = re.compile(
    r"saddr\s+@(\w+)\s+counter\s+packets\s+(\d+)\s+bytes\s+(\d+)\s+drop"
)


def parse_drop_counters(dump: str) -> dict[str, tuple[int, int]]:
    """Parse per-set ``(packets, bytes)`` drop counters from an nft table dump.

    Pure: no nft, no root. Returns an empty dict when the dump has no counters
    (e.g. an older table built before the drop rules carried ``counter``).
    """
    return {
        name: (int(pkts), int(byts))
        for name, pkts, byts in _DROP_COUNTER_RE.findall(dump)
    }


def drop_counters() -> dict[str, tuple[int, int]]:
    """Live per-set drop counters from kevward's table (read-only, fail-soft).

    Empty when nft is unavailable, the table is absent, or no counters exist.
    Counters reset whenever the ruleset is (re-)loaded, so callers should frame
    the numbers as "since the last ruleset load", not an all-time total.
    """
    if not nft_available():
        return {}
    r = _nft(["list", "table", "inet", TABLE])
    if not r.ok:
        return {}
    return parse_drop_counters(r.out)


def parse_unit_timestamp(out: str) -> int | None:
    """Epoch seconds from ``systemctl show -p X --timestamp=unix`` output
    (``X=@1731380401``), or None when unset/unparseable. Pure."""
    _, _, val = out.strip().partition("=")
    val = val.strip()
    if val.startswith("@") and val[1:].isdigit():
        return int(val[1:]) or None
    return None


def counters_since() -> int | None:
    """When kevward's drop counters were last reset (epoch seconds), or None.

    Read-only. The counters reset whenever the drop rules are recreated: by
    ``kevward firewall apply`` (which writes COUNTERS_STAMP) or by the boot
    unit reloading the saved ruleset (its ActiveEnterTimestamp). The later of
    the two is the start of the window the report's numbers cover.
    """
    times: list[int] = []
    try:
        with open(COUNTERS_STAMP) as fh:
            times.append(int(fh.read().strip()))
    except (OSError, ValueError):
        pass
    r = run(["systemctl", "show", "-p", "ActiveEnterTimestamp",
             "--timestamp=unix", PERSIST_UNIT], timeout=10)
    if r.ok:
        ts = parse_unit_timestamp(r.out)
        if ts:
            times.append(ts)
    return max(times) if times else None


def table_state() -> dict:
    """Is kevward's table loaded, and is the boot unit enabled? (read-only).

    ``table`` is None when it can't be judged (no nft, or not root). The
    report flags ``table is False`` with the unit enabled: the blocklist was
    meant to be on but isn't (e.g. the boot-time reload failed).
    """
    unit = run(["systemctl", "is-enabled", PERSIST_UNIT], timeout=10).out.strip()
    if not (nft_available() and is_root()):
        return {"table": None, "unit": unit}
    return {"table": _nft(["list", "table", "inet", TABLE]).ok, "unit": unit}


def _split_v4_v6(cidrs: list[str]) -> tuple[list[str], list[str]]:
    """Partition CIDRs/IPs into v4 and v6; silently drop unparseable entries."""
    v4: list[str] = []
    v6: list[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        (v6 if net.version == 6 else v4).append(c)
    return v4, v6


def _add_plain(setname: str, items: list[str]) -> tuple[int, list[str]]:
    """Add items with no timeout to a set, skipping any already present."""
    todo = [x for x in items if x not in _set_elements(setname)]
    if not todo:
        return 0, []
    r = _nft(["add", "element", "inet", TABLE, setname, "{ " + ", ".join(todo) + " }"])
    return (len(todo), []) if r.ok else (0, [r.err.strip() or f"failed adding to {setname}"])


def apply_allowset(cidrs: list[str]) -> tuple[int, list[str]]:
    """Populate the accept sets so the allowlist wins at the nft level too
    (including over a permanent block). Overlapping ranges auto-merge."""
    v4, v6 = _split_v4_v6(cidrs)
    a, e1 = _add_plain(ALLOW4, v4)
    b, e2 = _add_plain(ALLOW6, v6)
    return a + b, e1 + e2


def apply_blockset(cidrs: list[str]) -> tuple[int, list[str]]:
    """Add operator-configured permanent blocks (CIDR or IP, no TTL)."""
    v4, v6 = _split_v4_v6(cidrs)
    a, e1 = _add_plain(BLOCKCIDR4, v4)
    b, e2 = _add_plain(BLOCKCIDR6, v6)
    return a + b, e1 + e2


# --------------------------------------------------------------------------- #
# Reboot-persistence (issue #12): save kevward's table and reload it on boot.
# --------------------------------------------------------------------------- #
def _strip_runtime_state(dump: str) -> str:
    """Remove output-only state (``expires``) so an ``nft list`` dump reloads
    cleanly with ``nft -f``. Element timeouts are preserved (reset on boot).

    The value must stop at the element separator: ``\\S+`` used to swallow the
    trailing comma (``expires 13d2h,``), leaving ``a timeout 14d b timeout 14d``
    which ``nft -f`` rejects, so the table silently vanished on reboot."""
    return re.sub(r"\s+expires\s+[^\s,}]+", "", dump)


def persist_ruleset() -> tuple[bool, str]:
    """Save the current table to PERSIST_FILE and install a boot unit that
    reloads it, so the blocklist survives a reboot. Mirrors kevward-harden."""
    if not is_root():
        return False, "root required"
    r = _nft(["list", "table", "inet", TABLE])
    if not r.ok:
        return False, r.err.strip() or "could not read table"
    body = _strip_runtime_state(r.out)
    # declare -> delete -> define keeps the reload idempotent across boots.
    content = f"table inet {TABLE}\ndelete table inet {TABLE}\n{body}"
    nftpath = which("nft") or "/usr/sbin/nft"
    try:
        os.makedirs(os.path.dirname(PERSIST_FILE), exist_ok=True)
        with open(PERSIST_FILE, "w") as fh:
            fh.write(content)
    except OSError as e:
        return False, f"write failed: {e}"
    # Never arm the boot unit with a file nft would reject: that fails only at
    # the next reboot, silently, leaving the host without its blocklist.
    chk = _nft(["-c", "-f", PERSIST_FILE])
    if not chk.ok:
        first = (chk.err.strip().splitlines() or ["syntax error"])[0]
        return False, f"saved ruleset failed `nft -c` validation: {first}"
    try:
        with open(PERSIST_UNIT_FILE, "w") as fh:
            fh.write(_UNIT_TEMPLATE.format(nft=nftpath, file=PERSIST_FILE))
    except OSError as e:
        return False, f"write failed: {e}"
    run(["systemctl", "daemon-reload"], timeout=20)
    r2 = run(["systemctl", "enable", PERSIST_UNIT], timeout=20)
    return (True, "enabled (reapplied on boot)") if r2.ok else \
        (False, r2.err.strip() or "systemctl enable failed")


def remove_persistence() -> None:
    """Remove the boot unit and saved ruleset (used by flush). Best-effort."""
    run(["systemctl", "disable", "--now", PERSIST_UNIT], timeout=20)
    for path in (PERSIST_UNIT_FILE, PERSIST_FILE):
        try:
            os.remove(path)
        except OSError:
            pass
    run(["systemctl", "daemon-reload"], timeout=20)


def current_block_cidrs() -> list[str]:
    """Operator permanent blocks currently in kevward's table (read-only)."""
    return sorted(_set_elements(BLOCKCIDR4) | _set_elements(BLOCKCIDR6))


def prune_covered(cidrs: list[str]) -> tuple[int, list[str]]:
    """Remove evidence IPs that a permanent-block CIDR already covers.

    Housekeeping only: the CIDR keeps dropping them, so nothing is unblocked.
    Returns (removed, errors).
    """
    removed = 0
    errors: list[str] = []
    for setname in (SET4, SET6):
        stale = sorted(ip for ip in _set_elements(setname) if covered_by(ip, cidrs))
        if not stale:
            continue
        r = _nft(["delete", "element", "inet", TABLE, setname,
                  "{ " + ", ".join(stale) + " }"])
        if r.ok:
            removed += len(stale)
        else:
            errors.append(r.err.strip() or f"failed pruning {setname}")
    return removed, errors


def add_elements(ips: list[str], ttl_s: int) -> tuple[int, list[str]]:
    """Add IPs to the appropriate set with a timeout. Returns (added, errors)."""
    errors: list[str] = []
    added = 0
    for setname, group in (
        (SET4, [ip for ip in ips if ":" not in ip]),
        (SET6, [ip for ip in ips if ":" in ip]),
    ):
        if not group:
            continue
        elems = ", ".join(f"{ip} timeout {ttl_s}s" for ip in group)
        r = _nft(["add", "element", "inet", TABLE, setname, "{ " + elems + " }"])
        if r.ok:
            added += len(group)
        else:
            errors.append(r.err.strip() or f"failed adding to {setname}")
    return added, errors


def flush_table() -> tuple[bool, str]:
    if not nft_available():
        return False, "nftables (nft) not found"
    if not is_root():
        return False, "root required"
    if not _nft(["list", "table", "inet", TABLE]).ok:
        return True, "nothing to remove"
    r = _nft(["delete", "table", "inet", TABLE])
    return (r.ok, "removed" if r.ok else (r.err.strip() or "delete failed"))


# --------------------------------------------------------------------------- #
# CLI orchestration (kept here so cli.py stays thin)
# --------------------------------------------------------------------------- #
def _plan_data(min_sshd: int, extra_allow: list[str],
               block: list[str] | None = None) -> dict:
    allow = Allowlist.build(extra_allow, current_admin_ips())
    candidates = gather_candidates(min_sshd)
    selected = select(candidates, allow)
    skipped = [c for c in candidates if allow.allows(c.ip)]
    present: set[str] = set()
    cidrs = list(block or [])
    nft_ok = nft_available() and is_root()
    if nft_ok:
        present = current_set_ips()
        cidrs += [c for c in current_block_cidrs() if c not in cidrs]
    covered = {c.ip: cov for c in selected if (cov := covered_by(c.ip, cidrs))}
    to_add = [c for c in selected if c.ip not in present and c.ip not in covered]
    return {
        "block_cidrs": cidrs,
        "cidr_covered": covered,
        "nft_available": nft_available(),
        "root": is_root(),
        "candidates": len(candidates),
        "selected": selected,
        "to_add": to_add,
        "already_present": sorted(present & {c.ip for c in selected}),
        "allowlisted_skipped": [c.ip for c in skipped],
    }


# --------------------------------------------------------------------------- #
# Optional DNSBL cross-check (opt-in; off by default -> no network call).
# Confirms (or just annotates) that an IP is also flagged by a DNS blocklist,
# to reduce false positives before blocking. stdlib-only: a minimal UDP DNS
# query to a *configurable* resolver (DNSBLs rate-limit per resolver, and big
# public resolvers like 8.8.8.8 are blocked by Spamhaus). Fail soft: any
# error / timeout / blocked-resolver code is "unknown" and never blocks.
# --------------------------------------------------------------------------- #
_DNSBL_MALICIOUS = {f"127.0.0.{i}" for i in (2, 3, 4, 5, 6, 7, 9)}  # SBL/XBL/CBL
DNSBL_CACHE = "/var/cache/kevward/dnsbl.json"


def _dns_build_query(name: str) -> tuple[bytes, int]:
    tid = secrets.randbits(16)
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return hdr + q, tid


def _dns_skip_name(data: bytes, off: int) -> int:
    while off < len(data):
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:  # compression pointer ends the name
            return off + 2
        off += 1 + n
    return off


def _dns_parse(resp: bytes) -> tuple[int, list[str]]:
    """Return (rcode, [A-record IPs]). Tolerant, best-effort."""
    if len(resp) < 12:
        return (-1, [])
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        off = _dns_skip_name(resp, off) + 4  # + qtype + qclass
    ips: list[str] = []
    for _ in range(an):
        off = _dns_skip_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return (rcode, ips)


def classify_dnsbl(rcode: int, ips: list[str]) -> str:
    """'clean' / 'malicious' / 'policy' / 'unknown'. Conservative: anything we
    are not sure is malicious is never treated as a reason to block."""
    if rcode == 3:        # NXDOMAIN -> not listed
        return "clean"
    if rcode != 0:
        return "unknown"
    if not ips:
        return "clean"
    if any(ip.startswith("127.255.255.") for ip in ips):
        return "unknown"  # open-resolver / rate-limited / blocked
    if any(ip in _DNSBL_MALICIOUS for ip in ips):
        return "malicious"
    return "policy"       # PBL or other listing -> weak signal, don't block


def _default_resolver() -> str | None:
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return None


def dnsbl_lookup(ip: str, *, zone: str, resolver: str | None = None,
                 timeout: float = 3.0) -> str:
    octets = ip.split(".")
    if len(octets) != 4:  # IPv6 not supported in this MVP
        return "unknown"
    res = resolver or _default_resolver()
    if not res:
        return "unknown"
    name = ".".join(reversed(octets)) + "." + zone
    query, _ = _dns_build_query(name)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(query, (res, 53))
            resp, _addr = s.recvfrom(512)
        finally:
            s.close()
    except OSError:
        return "unknown"  # fail soft
    return classify_dnsbl(*_dns_parse(resp))


def _load_cache() -> dict:
    try:
        with open(DNSBL_CACHE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(DNSBL_CACHE), exist_ok=True)
        with open(DNSBL_CACHE, "w") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


def reputation_for(candidates: list[Candidate], *, zone: str,
                   resolver: str | None, top_n: int, cache_days: float) -> dict:
    """{ip: verdict} for the top_n candidates by score. Cache-aware; fail-soft;
    'unknown' is never cached so it is re-checked next time."""
    top = sorted(candidates, key=lambda c: c.score, reverse=True)[:max(0, top_n)]
    cache = _load_cache()
    now = time.time()
    ttl = cache_days * 86400
    rep: dict[str, str] = {}
    changed = False
    for c in top:
        ent = cache.get(c.ip)
        if ent and (now - ent.get("ts", 0)) < ttl:
            rep[c.ip] = ent["verdict"]
            continue
        v = dnsbl_lookup(c.ip, zone=zone, resolver=resolver)
        rep[c.ip] = v
        if v != "unknown":
            cache[c.ip] = {"verdict": v, "ts": now}
            changed = True
    if changed:
        _save_cache(cache)
    return rep


def run_cli(action: str, *, ttl_days: float, min_sshd: int,
            extra_allow: list[str], yes: bool, use_json: bool,
            block: list[str] | None = None, persist: bool = True,
            check_dnsbl: bool = False, require_reputation: bool = False,
            dnsbl_zone: str = "zen.spamhaus.org", dnsbl_resolver: str | None = None,
            dnsbl_top_n: int = 10, dnsbl_cache_days: float = 7.0) -> int:
    block = list(block or [])
    if action in ("plan", "apply"):
        data = _plan_data(min_sshd, extra_allow, block)
        to_add = data["to_add"]
        rep: dict[str, str] = {}
        if check_dnsbl:
            rep = reputation_for(to_add, zone=dnsbl_zone, resolver=dnsbl_resolver,
                                 top_n=dnsbl_top_n, cache_days=dnsbl_cache_days)
            if require_reputation:
                # confirm mode: block only candidates confirmed malicious by DNSBL
                to_add = [c for c in to_add if rep.get(c.ip) == "malicious"]
        if use_json:
            out = {
                "action": action,
                "nft_available": data["nft_available"],
                "root": data["root"],
                "ttl_days": ttl_days,
                "candidates": data["candidates"],
                "to_add": [vars(c) for c in to_add],
                "already_present": data["already_present"],
                "allowlisted_skipped": data["allowlisted_skipped"],
                "cidr_covered": data["cidr_covered"],
                "permanent_blocks": block,
                "persist": persist,
                "dnsbl": {"enabled": check_dnsbl,
                          "mode": "confirm" if require_reputation else "enrich",
                          "zone": dnsbl_zone, "verdicts": rep} if check_dnsbl else None,
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            if not data["nft_available"]:
                print("note: nftables (nft) not found -- showing candidates only.")
            if not data["root"]:
                print("note: not root -- evidence and set state may be incomplete.")
            if check_dnsbl:
                mode = "confirm (block only DNSBL-malicious)" if require_reputation \
                    else "enrich (annotate only)"
                print(f"note: DNSBL cross-check on top {dnsbl_top_n} via "
                      f"{dnsbl_zone} -- mode: {mode} (unknown never blocks)")
            print(f"candidates: {data['candidates']}  "
                  f"allowlisted (never blocked): {len(data['allowlisted_skipped'])}  "
                  f"already in set: {len(data['already_present'])}  "
                  f"covered by permanent CIDR: {len(data['cidr_covered'])}")
            print(f"would add {len(to_add)} IP(s)  (TTL {ttl_days:g}d):")
            for c in to_add[:100]:
                tag = f"  [DNSBL: {rep[c.ip]}]" if c.ip in rep else ""
                print(f"  + {c.ip:<39} {c.reason}{tag}")
            if len(to_add) > 100:
                print(f"  ... and {len(to_add) - 100} more")
            if block:
                shown = ", ".join(block[:8]) + (" ..." if len(block) > 8 else "")
                print(f"permanent blocks (config, no TTL): {len(block)} -> {shown}")
            print(f"reboot-persistence: {'on' if persist else 'off (--no-persist)'}")

        if action == "plan":
            return 0
        # apply
        if not yes:
            print("\nDRY RUN (pass --yes to actually update the firewall)")
            return 0
        ok, msg = ensure_table()
        if not ok:
            print(f"refused: {msg}")
            return 2
        # Allowlist -> accept set, so it wins at the nft level too (incl. over a
        # permanent block). Only *stable* entries are persisted here: the floor,
        # configured CIDRs, and the running session's own SSH source. Transient
        # established-:22 peers are deliberately excluded (issue #17).
        allow_cidrs = list(_DEFAULT_ALLOW) + list(extra_allow) + sorted(session_admin_ips())
        apply_allowset(allow_cidrs)
        perm_added, perm_err = apply_blockset(block)
        added, errors = add_elements([c.ip for c in to_add], ttl_seconds(ttl_days))
        errors += perm_err
        # Evidence entries a permanent CIDR now covers are redundant: drop them
        # so `firewall list` shows what is actually new (still blocked by CIDR).
        pruned, prune_err = prune_covered(sorted(set(block) | set(current_block_cidrs())))
        errors += prune_err
        print(f"added {added} IP(s) to the kevward blocklist (nft inet {TABLE}).")
        if pruned:
            print(f"pruned {pruned} IP(s) already covered by a permanent CIDR block.")
        if block:
            print(f"permanent blocks: {perm_added} new, {len(block)} configured.")
        if persist:
            pok, pmsg = persist_ruleset()
            print(f"reboot-persistence: {pmsg}" if pok
                  else f"reboot-persistence: not enabled ({pmsg})")
        else:
            print("reboot-persistence: skipped (--no-persist)")
        for e in errors:
            print(f"  ! {e}")
        return 0 if not errors else 1

    if action == "list":
        if not (nft_available() and is_root()):
            print("note: needs nftables + root to read the live set.")
            return 2
        shown = 0
        for setname in (ALLOW4, ALLOW6, SET4, SET6, BLOCKCIDR4, BLOCKCIDR6):
            r = _nft(["list", "set", "inet", TABLE, setname])
            if r.ok:
                print(r.out.rstrip())
                shown += 1
        unit = run(["systemctl", "is-enabled", PERSIST_UNIT], timeout=10).out.strip()
        print(f"reboot-persistence unit: {unit or 'not installed'}")
        if not shown:
            print(f"! kevward table not loaded (nft inet {TABLE} is absent).")
            if unit == "enabled":
                print(f"  the boot unit is enabled, so its reload likely failed: "
                      f"systemctl status {PERSIST_UNIT}")
            print("  re-create it with: kevward firewall apply --yes")
            return 1
        return 0

    if action == "flush":
        if not yes:
            print("refused: pass --yes to remove kevward's blocklist.")
            return 2
        ok, msg = flush_table()
        remove_persistence()
        print(msg if ok else f"refused: {msg}")
        return 0 if ok else 2

    print(f"unknown firewall action: {action}")
    return 2
