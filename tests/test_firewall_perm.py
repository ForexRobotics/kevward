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
    assert snip.index(f"@{fw.ALLOW4} accept") < snip.index(f"@{fw.SET4} drop")
    assert snip.index(f"@{fw.SET4} drop") < snip.index(f"@{fw.BLOCKCIDR4} drop")
    # CIDR support: permanent/allow sets are interval sets; evidence is TTL'd
    assert f"set {fw.BLOCKCIDR4} {{ type ipv4_addr; flags interval; auto-merge; }}" in snip
    assert f"set {fw.SET4} {{ type ipv4_addr; flags timeout; }}" in snip


def test_strip_runtime_state_drops_expires_keeps_timeout():
    dump = "elements = { 1.2.3.4 timeout 14d expires 13d20h14m58s492ms }"
    out = fw._strip_runtime_state(dump)
    assert "expires" not in out
    assert "timeout 14d" in out
    assert out == "elements = { 1.2.3.4 timeout 14d }"


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
