"""Unit tests for harden's pure-logic parsers (no root / nft / systemd needed).

Runnable with pytest, or directly: ``python tests/test_harden.py``.
"""

from __future__ import annotations

from kevward import harden


def test_parse_livepatch_enabled():
    txt = (
        "SERVICE          ENTITLED  STATUS\n"
        "esm-infra        yes       enabled\n"
        "livepatch        yes       enabled\n"
    )
    assert harden.parse_livepatch(txt) == "enabled"


def test_parse_livepatch_not_attached():
    # The "AVAILABLE" column format appears when the machine is not attached.
    txt = (
        "This machine is not attached to an Ubuntu Pro subscription.\n"
        "SERVICE          AVAILABLE  DESCRIPTION\n"
        "livepatch        yes        Canonical Livepatch service\n"
    )
    assert harden.parse_livepatch(txt) == "not-attached"


def test_parse_livepatch_disabled_when_attached():
    txt = (
        "SERVICE          ENTITLED  STATUS\n"
        "esm-infra        yes       enabled\n"
        "livepatch        yes       disabled\n"
    )
    assert harden.parse_livepatch(txt) == "disabled"


def test_nft_ruleset_is_idempotent_and_owns_its_table():
    rs = harden._nft_ruleset()
    # declare + delete + define == safe to re-load on every boot
    assert f"table inet {harden.NFT_TABLE}\n" in rs
    assert f"delete table inet {harden.NFT_TABLE}\n" in rs
    assert "ip hdrlength != 5 counter drop" in rs
    # never touches anything but its own table
    assert "kevward_cve" not in rs
    assert "ufw" not in rs.lower()


def test_unit_execstart_is_absolute():
    unit = harden._unit_file()
    # systemd requires an absolute ExecStart path
    assert "ExecStart=/" in unit
    assert harden.NFT_FILE in unit
    assert "WantedBy=multi-user.target" in unit


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all harden tests passed")
