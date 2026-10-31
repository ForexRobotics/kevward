"""Host hardening: read-only checks + a small set of safe, reversible,
kevward-owned interim mitigations. Local host only, defensive.

Motivated by real incidents where the fixed kernel lags for days (e.g.
CVE-2026-98432): until the patch ships you want to *know your posture* and
apply a few interim mitigations — and have them survive a reboot.

What `apply` does (opt-in, dry-run by default):
- ``--mptcp-off``: disable MPTCP kernel-wide via a kevward-owned sysctl drop-in
  (closes the demonstrated root-exploit path). Persistent by nature.
- ``--drop-ip-options``: drop inbound IPv4 packets carrying IP options (the
  crafted-SYN trigger; normal IHL == 5) via a kevward-owned nftables table,
  AND install a tiny systemd unit so it is re-applied on every boot.

Everything here lives in kevward's own namespace and is fully reversible:
- ``/etc/sysctl.d/99-kevward-mptcp.conf``
- ``/etc/kevward/harden.nft``  (table ``inet kevward_harden``)
- ``/etc/systemd/system/kevward-harden.service``

It never edits SSH config or the user's ufw/nft rules, and never calls out.
"""

from __future__ import annotations

import os
import re

from .model import Finding, FindingKind, Severity
from .util import have, is_root, reboot_pending, run, which

SYSCTL_FILE = "/etc/sysctl.d/99-kevward-mptcp.conf"
NFT_TABLE = "kevward_harden"
NFT_FILE = "/etc/kevward/harden.nft"
UNIT_FILE = "/etc/systemd/system/kevward-harden.service"
UNIT_NAME = "kevward-harden.service"

# sysctls we check, with the value we consider hardened.
_RECOMMENDED = {
    "net.mptcp.enabled": "0",
    "net.ipv4.tcp_migrate_req": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
}


# --------------------------------------------------------------------------- #
# Read-only checks
# --------------------------------------------------------------------------- #
def _sysctl(key: str) -> str | None:
    r = run(["sysctl", "-n", key], timeout=10)
    return r.out.strip() if r.ok else None


def running_kernel() -> str:
    r = run(["uname", "-r"], timeout=10)
    return r.out.strip()


def newest_installed_kernel() -> str | None:
    """Highest-versioned installed linux-image-<ver>-<flavour>, best-effort."""
    r = run(["dpkg-query", "-W", "-f=${Package}\n", "linux-image-*"], timeout=20)
    if not r.ok:
        return None
    vers = []
    for pkg in r.out.split():
        m = re.match(r"linux-image-(\d+\.\d+\.\d+-\d+)-", pkg)
        if m:
            vers.append(m.group(1))
    if not vers:
        return None

    def key(v: str):
        return [int(x) for x in re.split(r"[.-]", v)]

    return sorted(vers, key=key)[-1]


def parse_livepatch(pro_status_text: str) -> str:
    """'enabled' / 'disabled' / 'not-attached' from `pro status` output.

    The status column's position differs between the attached layout
    (SERVICE ENTITLED STATUS) and the unattached one (SERVICE AVAILABLE
    DESCRIPTION), so match on the status token anywhere on the livepatch line.
    """
    attached = "not attached" not in pro_status_text.lower()
    for line in pro_status_text.splitlines():
        if line.lower().startswith("livepatch"):
            toks = [t.lower() for t in line.split()]
            for status in ("enabled", "disabled", "warning"):
                if status in toks:
                    return status
    return "disabled" if attached else "not-attached"


def livepatch_status() -> str:
    if not have("pro"):
        return "pro-not-installed"
    r = run(["pro", "status"], timeout=30)
    return parse_livepatch(r.out) if r.ok else "unknown"


def public_listeners() -> list[str]:
    """Ports listening on a non-loopback address (can complete a handshake)."""
    r = run(["ss", "-tlnH"], timeout=10)
    out: list[str] = []
    if not r.ok:
        return out
    for line in r.out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if local.startswith(("127.", "[::1]")):
            continue
        port = local.rsplit(":", 1)[-1]
        if port.isdigit():
            out.append(port)
    return sorted(set(out), key=int)


def check() -> list[Finding]:
    """Read-only hardening posture. Never changes anything."""
    f: list[Finding] = []

    run_k = running_kernel()
    newest = newest_installed_kernel()
    if newest and newest not in run_k:
        f.append(Finding(
            "harden", FindingKind.CONFIG, Severity.MEDIUM,
            f"Running kernel {run_k} but {newest} is installed — reboot to apply",
            reboot_required=True,
        ))
    elif reboot_pending():
        f.append(Finding(
            "harden", FindingKind.CONFIG, Severity.MEDIUM,
            "Reboot required to finish applying installed updates",
            reboot_required=True,
        ))

    for key, want in _RECOMMENDED.items():
        cur = _sysctl(key)
        if cur is not None and cur != want:
            f.append(Finding(
                "harden", FindingKind.CONFIG, Severity.LOW,
                f"sysctl {key} = {cur} (recommended {want})",
                detail="apply with: kevward harden apply --yes",
            ))

    lp = livepatch_status()
    if lp in ("disabled", "not-attached"):
        f.append(Finding(
            "harden", FindingKind.CONFIG, Severity.INFO,
            "Ubuntu Livepatch not active — kernel fixes need a reboot",
            detail=f"status: {lp}. Attaching Ubuntu Pro (free tier) enables it.",
        ))

    ports = public_listeners()
    if ports:
        f.append(Finding(
            "harden", FindingKind.CONFIG, Severity.INFO,
            f"Public TCP listeners: {', '.join(ports)}",
            detail="These can complete a TCP handshake from anywhere.",
        ))
    return f


# --------------------------------------------------------------------------- #
# Mitigations (apply / revert) — kevward-owned, reversible
# --------------------------------------------------------------------------- #
def _nft_ruleset() -> str:
    # The declare+delete+define idiom makes re-loading idempotent (on boot too).
    return (
        "#!/usr/sbin/nft -f\n"
        "# kevward harden: drop inbound IPv4 packets carrying IP options.\n"
        f"table inet {NFT_TABLE}\n"
        f"delete table inet {NFT_TABLE}\n"
        f"table inet {NFT_TABLE} {{\n"
        "  chain input {\n"
        "    type filter hook input priority -160; policy accept\n"
        "    ip hdrlength != 5 counter drop\n"
        "  }\n"
        "}\n"
    )


def _unit_file() -> str:
    nft = which("nft") or "/usr/sbin/nft"
    return (
        "[Unit]\n"
        "Description=kevward harden: reapply host hardening nftables rules\n"
        "After=network-pre.target\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={nft} -f {NFT_FILE}\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def apply_mptcp_off() -> list[str]:
    msgs = []
    os.makedirs(os.path.dirname(SYSCTL_FILE), exist_ok=True)
    with open(SYSCTL_FILE, "w") as fh:
        fh.write(
            "# kevward harden: no standard service needs MPTCP; disabling it\n"
            "# removes the MPTCP code path.\n"
            "net.mptcp.enabled=0\n"
        )
    run(["sysctl", "-w", "net.mptcp.enabled=0"], timeout=10)
    msgs.append(f"mptcp disabled (persisted in {SYSCTL_FILE})")
    return msgs


def apply_ip_options_drop(persist: bool = True) -> list[str]:
    msgs = []
    os.makedirs(os.path.dirname(NFT_FILE), exist_ok=True)
    with open(NFT_FILE, "w") as fh:
        fh.write(_nft_ruleset())
    r = run(["nft", "-f", NFT_FILE], timeout=15)
    if not r.ok:
        return [f"FAILED to load nft ruleset: {r.err.strip()}"]
    msgs.append(f"ip-options drop active (table inet {NFT_TABLE})")
    if persist:
        with open(UNIT_FILE, "w") as fh:
            fh.write(_unit_file())
        run(["systemctl", "daemon-reload"], timeout=20)
        run(["systemctl", "enable", UNIT_NAME], timeout=20)
        msgs.append(f"reboot-persistent via {UNIT_NAME} (re-applied on boot)")
    return msgs


def revert() -> list[str]:
    msgs = []
    if os.path.exists(SYSCTL_FILE):
        os.remove(SYSCTL_FILE)
        run(["sysctl", "-w", "net.mptcp.enabled=1"], timeout=10)
        msgs.append("mptcp re-enabled; sysctl drop-in removed")
    run(["systemctl", "disable", "--now", UNIT_NAME], timeout=20)
    if os.path.exists(UNIT_FILE):
        os.remove(UNIT_FILE)
        run(["systemctl", "daemon-reload"], timeout=20)
    run(["nft", "delete", "table", "inet", NFT_TABLE], timeout=15)
    if os.path.exists(NFT_FILE):
        os.remove(NFT_FILE)
    msgs.append(f"ip-options drop removed (table inet {NFT_TABLE}, unit, nft file)")
    return msgs


def state() -> dict:
    return {
        "mptcp_enabled": _sysctl("net.mptcp.enabled"),
        "mptcp_dropin": os.path.exists(SYSCTL_FILE),
        "ip_options_table": run(
            ["nft", "list", "table", "inet", NFT_TABLE], timeout=10
        ).ok,
        "boot_unit_enabled": run(
            ["systemctl", "is-enabled", UNIT_NAME], timeout=10
        ).out.strip() == "enabled",
    }


# --------------------------------------------------------------------------- #
# CLI orchestration
# --------------------------------------------------------------------------- #
def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("  ok — no hardening findings")
        return
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        print(f"  - {sev.upper():7} {f.title}")
        if f.detail:
            print(f"            {f.detail}")


def run_cli(action: str, *, mptcp_off: bool, drop_ip_options: bool,
            persist: bool, yes: bool, use_json: bool) -> int:
    if action == "check":
        findings = check()
        if use_json:
            import json
            print(json.dumps([f.to_dict() for f in findings], indent=2,
                             ensure_ascii=False))
        else:
            _print_findings(findings)
        return 0

    if action == "list":
        st = state()
        if use_json:
            import json
            print(json.dumps(st, indent=2))
        else:
            for k, v in st.items():
                print(f"  {k}: {v}")
        return 0

    # If no mitigation flag was given, apply/plan both (the common case).
    if not (mptcp_off or drop_ip_options):
        mptcp_off = drop_ip_options = True

    if action in ("plan", "apply"):
        planned = []
        if mptcp_off:
            planned.append(f"disable MPTCP (write {SYSCTL_FILE})")
        if drop_ip_options:
            planned.append(f"drop IPv4 IP-options (table inet {NFT_TABLE})"
                           + (" + boot-persistent unit" if persist else ""))
        for p in planned:
            print(f"  would: {p}")
        if action == "plan":
            return 0
        if not yes:
            print("\nDRY RUN (pass --yes to apply)")
            return 0
        if not is_root():
            print("refused: root required")
            return 2
        if not have("nft") and drop_ip_options:
            print("refused: nftables (nft) not found")
            return 2
        done = []
        if mptcp_off:
            done += apply_mptcp_off()
        if drop_ip_options:
            done += apply_ip_options_drop(persist=persist)
        print()
        for d in done:
            print(f"  {d}")
        return 0

    if action == "revert":
        if not yes:
            print("refused: pass --yes to revert kevward's hardening")
            return 2
        if not is_root():
            print("refused: root required")
            return 2
        for d in revert():
            print(f"  {d}")
        return 0

    print(f"unknown harden action: {action}")
    return 2
