# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#251: never block the multipass host from inside a multipass guest."""

from __future__ import annotations

import json

from kevward import firewall as fw

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ens3\t00000000\t0140A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
ens3\t0040A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""
ROUTE6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
          "fe800000000000005054fffffe000001 00000400 00000001 00000000 00000003 ens3\n")
KEY = "ssh-rsa AAAAB3Nza multipass@localhost\n"


def test_default_gateways():
    assert fw.default_gateways(ROUTE, ROUTE6) == ["192.168.64.1", "fe80::5054:ffff:fe00:1"]
    assert fw.default_gateways("", "") == []


def test_multipass_guest():
    assert fw.multipass_guest("nocloud\n", [KEY])
    assert not fw.multipass_guest("ec2\n", [KEY])                 # other cloud
    assert not fw.multipass_guest("nocloud\n", ["ssh-ed25519 AAAA me@pc\n"])  # plain VM
    assert not fw.multipass_guest("nocloud\n", ["# multipass\n"])


def _tree(tmp_path, cloud_id="nocloud", key=KEY, route=ROUTE):
    (tmp_path / "run/cloud-init").mkdir(parents=True)
    (tmp_path / "run/cloud-init/cloud-id").write_text(cloud_id + "\n")
    (tmp_path / "home/ubuntu/.ssh").mkdir(parents=True)
    (tmp_path / "home/ubuntu/.ssh/authorized_keys").write_text(key)
    (tmp_path / "proc/net").mkdir(parents=True)
    (tmp_path / "proc/net/route").write_text(route)
    (tmp_path / "proc/net/ipv6_route").write_text(ROUTE6)
    return str(tmp_path)


def test_multipass_gateways(tmp_path):
    assert fw.multipass_gateways(_tree(tmp_path)) == ["192.168.64.1", "fe80::5054:ffff:fe00:1"]


def test_not_multipass(tmp_path):
    assert fw.multipass_gateways(_tree(tmp_path, cloud_id="lxd")) == []


def test_public_gateway_not_added(tmp_path):
    route = ROUTE.replace("0140A8C0", "01020304")   # 4.3.2.1: not the NAT host
    assert fw.multipass_gateways(_tree(tmp_path, route=route)) == ["fe80::5054:ffff:fe00:1"]


def test_plan_shows_gateway(monkeypatch, capsys):
    seen = {}

    def plan_data(min_sshd, extra_allow, block=None):
        seen["allow"] = list(extra_allow)
        return {"nft_available": False, "root": False, "candidates": 0, "to_add": [],
                "already_present": [], "allowlisted_skipped": [], "cidr_covered": {},
                "block_cidrs": [], "selected": []}

    monkeypatch.setattr(fw, "_plan_data", plan_data)
    fw.run_cli("plan", ttl_days=7, min_sshd=20, extra_allow=["203.0.113.9"], yes=False,
               use_json=False, gateways=["192.168.64.1"])
    assert seen["allow"] == ["203.0.113.9", "192.168.64.1"]
    assert "allowlisted: 192.168.64.1 (multipass host)" in capsys.readouterr().out
    fw.run_cli("plan", ttl_days=7, min_sshd=20, extra_allow=[], yes=False, use_json=True,
               gateways=["192.168.64.1"])
    assert json.loads(capsys.readouterr().out)["multipass_host"] == ["192.168.64.1"]
    fw.run_cli("plan", ttl_days=7, min_sshd=20, extra_allow=[], yes=False, use_json=True,
               gateways=["192.168.64.1"], allow_gateway=False)
    assert json.loads(capsys.readouterr().out)["multipass_host"] == []
