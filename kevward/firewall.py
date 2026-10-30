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
from dataclasses import dataclass, field

from .integrations import fail2ban, logwatch
from .util import have, is_root, run

# kevward-owned nftables objects. We only ever touch these.
TABLE = "kevward"
SET4 = "blocklist4"
SET6 = "blocklist6"
CHAIN = "input"

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
def current_admin_ips() -> set[str]:
    """IPs currently administering this host, so the operator is never blocked:
    this process's SSH_* env, plus established inbound SSH peers."""
    ips: set[str] = set()
    for var in ("SSH_CLIENT", "SSH_CONNECTION"):
        val = os.environ.get(var, "")
        if val:
            ips.add(val.split()[0])
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


def ensure_table() -> tuple[bool, str]:
    """Idempotently create kevward's table/sets/chain. Only our chain is ever
    flushed; existing sets (and their elements) are preserved."""
    if not nft_available():
        return False, "nftables (nft) not found"
    if not is_root():
        return False, "root required"
    if not _nft(["list", "table", "inet", TABLE]).ok:
        snippet = (
            f"table inet {TABLE} {{\n"
            f"  set {SET4} {{ type ipv4_addr; flags timeout; }}\n"
            f"  set {SET6} {{ type ipv6_addr; flags timeout; }}\n"
            f"  chain {CHAIN} {{\n"
            f"    type filter hook input priority -150; policy accept;\n"
            f"    ip saddr @{SET4} drop\n"
            f"    ip6 saddr @{SET6} drop\n"
            f"  }}\n"
            f"}}\n"
        )
        r = _nft(["-f", "-"], input_=snippet)
        if not r.ok:
            return False, r.err.strip() or "nft create failed"
    else:
        # Reassert only our own chain's rules; leaves set contents intact.
        _nft(["flush", "chain", "inet", TABLE, CHAIN])
        _nft(["add", "rule", "inet", TABLE, CHAIN, "ip", "saddr", f"@{SET4}", "drop"])
        _nft(["add", "rule", "inet", TABLE, CHAIN, "ip6", "saddr", f"@{SET6}", "drop"])
    return True, "ok"


def current_set_ips() -> set[str]:
    ips: set[str] = set()
    for setname in (SET4, SET6):
        r = _nft(["list", "set", "inet", TABLE, setname])
        if not r.ok:
            continue
        m = re.search(r"elements\s*=\s*\{(.*?)\}", r.out, re.S)
        if not m:
            continue
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok:
                ips.add(tok.split()[0])
    return ips


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
def _plan_data(min_sshd: int, extra_allow: list[str]) -> dict:
    allow = Allowlist.build(extra_allow, current_admin_ips())
    candidates = gather_candidates(min_sshd)
    selected = select(candidates, allow)
    skipped = [c for c in candidates if allow.allows(c.ip)]
    present: set[str] = set()
    nft_ok = nft_available() and is_root()
    if nft_ok:
        present = current_set_ips()
    to_add = [c for c in selected if c.ip not in present]
    return {
        "nft_available": nft_available(),
        "root": is_root(),
        "candidates": len(candidates),
        "selected": selected,
        "to_add": to_add,
        "already_present": sorted(present & {c.ip for c in selected}),
        "allowlisted_skipped": [c.ip for c in skipped],
    }


def run_cli(action: str, *, ttl_days: float, min_sshd: int,
            extra_allow: list[str], yes: bool, use_json: bool) -> int:
    if action in ("plan", "apply"):
        data = _plan_data(min_sshd, extra_allow)
        to_add = data["to_add"]
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
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            if not data["nft_available"]:
                print("note: nftables (nft) not found -- showing candidates only.")
            if not data["root"]:
                print("note: not root -- evidence and set state may be incomplete.")
            print(f"candidates: {data['candidates']}  "
                  f"allowlisted (never blocked): {len(data['allowlisted_skipped'])}  "
                  f"already in set: {len(data['already_present'])}")
            print(f"would add {len(to_add)} IP(s)  (TTL {ttl_days:g}d):")
            for c in to_add[:100]:
                print(f"  + {c.ip:<39} {c.reason}")
            if len(to_add) > 100:
                print(f"  ... and {len(to_add) - 100} more")

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
        added, errors = add_elements([c.ip for c in to_add], ttl_seconds(ttl_days))
        print(f"added {added} IP(s) to the kevward blocklist (nft inet {TABLE}).")
        for e in errors:
            print(f"  ! {e}")
        return 0 if not errors else 1

    if action == "list":
        if not (nft_available() and is_root()):
            print("note: needs nftables + root to read the live set.")
            return 2
        for setname in (SET4, SET6):
            r = _nft(["list", "set", "inet", TABLE, setname])
            if r.ok:
                print(r.out.rstrip())
        return 0

    if action == "flush":
        if not yes:
            print("refused: pass --yes to remove kevward's blocklist.")
            return 2
        ok, msg = flush_table()
        print(msg if ok else f"refused: {msg}")
        return 0 if ok else 2

    print(f"unknown firewall action: {action}")
    return 2
