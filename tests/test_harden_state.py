"""Unit tests for harden's nft table detection (tri-state, no root/network)."""

from __future__ import annotations

from kevward import harden as hd
from kevward.util import Cmd


def _patch(monkeypatch, *, has_nft=True, result=None):
    monkeypatch.setattr(hd, "have", lambda name: has_nft)
    if result is not None:
        monkeypatch.setattr(hd, "run", lambda *a, **k: result)


def test_table_present_is_true(monkeypatch):
    _patch(monkeypatch, result=Cmd(0, "table inet kevward_harden { }", ""))
    assert hd._nft_table_exists("kevward_harden") is True


def test_table_absent_is_false(monkeypatch):
    # nft, as root, when the table does not exist:
    _patch(monkeypatch, result=Cmd(1, "", "Error: No such file or directory"))
    assert hd._nft_table_exists("kevward_harden") is False


def test_permission_denied_is_unknown_not_false(monkeypatch):
    # nft queried without root must NOT be reported as "absent".
    _patch(monkeypatch, result=Cmd(1, "", "Error: Operation not permitted"))
    assert hd._nft_table_exists("kevward_harden") is None


def test_nft_missing_is_unknown(monkeypatch):
    _patch(monkeypatch, has_nft=False)
    assert hd._nft_table_exists("kevward_harden") is None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
