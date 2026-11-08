# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for the permanent-block list (#13) and reboot-persistence (#12)
helpers — the parts that don't need nft or root."""

from __future__ import annotations

from kevward import firewall as fw


def test_split_v4_v6_partitions_and_drops_garbage():
    v4, v6 = fw._split_v4_v6(
        ["109.160.32.0/24", "1.2.3.4", "2001:db8::/32", "::1", "not-an-ip"]
    )
    assert v4 == ["109.160.32.0/24", "1.2.3.4"]
    assert v6 == ["2001:db8::/32", "::1"]


def test_table_snippet_allowlist_accepts_before_it_drops():
    snip = fw._table_snippet()
    # allow sets are accepted before any drop -> allowlist wins over blocks
    assert snip.index(f"@{fw.ALLOW4} accept") < snip.index(f"@{fw.SET4} counter drop")
    assert snip.index(f"@{fw.SET4} counter drop") < snip.index(f"@{fw.BLOCKCIDR4} counter drop")
    # CIDR support: permanent/allow sets are interval sets; evidence is TTL'd
    assert f"set {fw.BLOCKCIDR4} {{ type ipv4_addr; flags interval; auto-merge; }}" in snip
    assert f"set {fw.SET4} {{ type ipv4_addr; flags timeout; }}" in snip


def test_table_snippet_drops_are_counted():
    # drop rules carry a counter so `nft list` shows how much each block set
    # actually catches; allow rules stay plain accepts (no counter).
    snip = fw._table_snippet()
    for s in (fw.SET4, fw.SET6, fw.BLOCKCIDR4, fw.BLOCKCIDR6):
        assert f"@{s} counter drop" in snip
    assert f"@{fw.ALLOW4} accept" in snip
    assert f"@{fw.ALLOW4} counter accept" not in snip


def test_strip_runtime_state_drops_expires_keeps_timeout():
    dump = "elements = { 1.2.3.4 timeout 14d expires 13d20h14m58s492ms }"
    out = fw._strip_runtime_state(dump)
    assert "expires" not in out
    assert "timeout 14d" in out
    assert out == "elements = { 1.2.3.4 timeout 14d }"


def test_strip_runtime_state_keeps_element_separators():
    # Real multi-element `nft list` output: `expires` sits right before the
    # comma. Dropping the comma made the saved file unloadable at boot.
    dump = (
        "\t\telements = { 2.57.121.25 timeout 14d expires 13d2h3m4s500ms, "
        "2.57.121.112 timeout 14d expires 9d1h,\n"
        "\t\t\t     2.57.122.74 timeout 14d expires 1h }"
    )
    out = fw._strip_runtime_state(dump)
    assert "expires" not in out
    assert out == (
        "\t\telements = { 2.57.121.25 timeout 14d, "
        "2.57.121.112 timeout 14d,\n"
        "\t\t\t     2.57.122.74 timeout 14d }"
    )


def test_persist_refuses_to_arm_unit_when_nft_rejects_file(monkeypatch, tmp_path):
    from types import SimpleNamespace as NS
    calls = []

    def fake_nft(args, input_=None):
        calls.append(args)
        if args[:1] == ["-c"]:
            return NS(ok=False, out="", err="firewall.nft:25: Error: syntax error\n")
        return NS(ok=True, out="table inet kevward {\n}\n", err="")

    monkeypatch.setattr(fw, "is_root", lambda: True)
    monkeypatch.setattr(fw, "_nft", fake_nft)
    monkeypatch.setattr(fw, "PERSIST_FILE", str(tmp_path / "firewall.nft"))
    unit = tmp_path / "kevward-firewall.service"
    monkeypatch.setattr(fw, "PERSIST_UNIT_FILE", str(unit))
    monkeypatch.setattr(fw, "run", lambda *a, **k: NS(ok=True, out="", err=""))
    ok, msg = fw.persist_ruleset()
    assert not ok
    assert "nft -c" in msg
    assert not unit.exists()                    # boot unit never armed
    assert ["-c", "-f", str(tmp_path / "firewall.nft")] in calls


def test_session_admin_ips_are_env_only_not_from_ss(monkeypatch):
    # The persisted accept set uses these; they must come only from the running
    # session's sshd env, never from an established-:22 scan (issue #17).
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.9 51530 10.0.0.1 22")
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    assert fw.session_admin_ips() == {"203.0.113.9"}
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    assert fw.session_admin_ips() == set()


def test_unit_template_is_a_oneshot_that_loads_the_saved_file():
    unit = fw._UNIT_TEMPLATE.format(nft="/usr/sbin/nft", file=fw.PERSIST_FILE)
    assert "Type=oneshot" in unit
    assert f"ExecStart=/usr/sbin/nft -f {fw.PERSIST_FILE}" in unit
    assert "WantedBy=multi-user.target" in unit


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all firewall-perm tests passed")
