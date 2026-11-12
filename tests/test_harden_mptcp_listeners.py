# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""harden: kernels without MPTCP, and loopback-bound listeners (no root/host)."""

from __future__ import annotations

from kevward import harden as hd
from kevward.util import Cmd

# `ss -tlnH` on Ubuntu 26.04 under WSL2 (trimmed) plus a few real listeners.
_SS = """\
LISTEN 0 1000 10.255.255.254:53 0.0.0.0:*
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
LISTEN 0 4096 127.0.0.54:53 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
LISTEN 0 511 [::]:443 [::]:*
LISTEN 0 128 [::1]:631 [::]:*
LISTEN 0 128 [fe80::1%lo]:8080 [::]:*
LISTEN 0 80 *:3306 *:*
"""

_TAIL = "\\       valid_lft forever preferred_lft forever"
_IP_LO = (
    f"1: lo    inet 127.0.0.1/8 scope host lo{_TAIL}\n"
    f"1: lo    inet 10.255.255.254/32 brd 10.255.255.254 scope global lo{_TAIL}\n"
    f"1: lo    inet6 ::1/128 scope host noprefixroute {_TAIL}\n"
)


def test_parse_lo_addrs():
    assert hd.parse_lo_addrs(_IP_LO) == {"127.0.0.1", "10.255.255.254", "::1"}
    assert hd.parse_lo_addrs("") == set()


def test_public_ports_skip_loopback_and_lo_addresses():
    lo = hd.parse_lo_addrs(_IP_LO)
    assert hd.parse_public_ports(_SS, lo) == ["22", "443", "3306"]


def test_public_ports_without_lo_info_still_skips_obvious_loopback():
    # 10.255.255.254 is only known to be local via `ip addr show dev lo`.
    assert hd.parse_public_ports(_SS) == ["22", "53", "443", "3306"]


def test_apply_mptcp_off_noop_when_kernel_lacks_mptcp(monkeypatch, tmp_path):
    monkeypatch.setattr(hd, "mptcp_supported", lambda: False)
    dropin = tmp_path / "99-kevward-mptcp.conf"
    monkeypatch.setattr(hd, "SYSCTL_FILE", str(dropin))
    msgs = hd.apply_mptcp_off()
    assert "not available in this kernel" in msgs[0]
    assert not dropin.exists()


def test_apply_mptcp_off_reports_sysctl_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(hd, "mptcp_supported", lambda: True)
    monkeypatch.setattr(hd, "SYSCTL_FILE", str(tmp_path / "d.conf"))
    monkeypatch.setattr(hd, "run", lambda *a, **k: Cmd(1, "", "permission denied"))
    msgs = hd.apply_mptcp_off()
    assert msgs[0].startswith("FAILED")


def test_list_text_distinguishes_missing_kernel_feature_from_root():
    st = {"mptcp_supported": False, "mptcp_enabled": None, "ip_options_table": None}
    d = hd.describe_state_value
    assert d("mptcp_enabled", None, st, root=True) == "n/a (not in this kernel)"
    assert d("ip_options_table", None, st, root=True) == "unknown"
    assert d("ip_options_table", None, st, root=False) == "unknown (run as root)"
    assert d("mptcp_dropin", False, st, root=True) == "False"
