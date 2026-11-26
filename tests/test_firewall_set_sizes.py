# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""The report shows how many entries each block set holds next to its drops."""

from __future__ import annotations

from kevward.engine import RunResult
from kevward.reporting.html import render
from kevward.util import Cmd

_SET4 = """table inet kevward {
        set blocklist4 {
                type ipv4_addr
                flags timeout
                elements = { 1.2.3.4 timeout 14d expires 13d2h, 5.6.7.8 timeout 14d expires 9d,
                             9.9.9.9 timeout 14d expires 1d }
        }
}"""


def _res(att):
    return RunResult(host="h", generated_at="2026-11-14T07:00:00+00:00",
                     os="Linux", attackers=att)


def test_set_sizes_counts_elements(monkeypatch):
    from kevward import firewall as fw

    def nft(args):
        if args[:2] == ["list", "table"]:
            return Cmd(0, "table inet kevward {}", "")
        if args[-1] == fw.SET4:
            return Cmd(0, _SET4, "")
        return Cmd(0, "set x { type ipv4_addr\n}", "")  # empty set: no elements line
    monkeypatch.setattr(fw, "nft_available", lambda: True)
    monkeypatch.setattr(fw, "is_root", lambda: True)
    monkeypatch.setattr(fw, "_nft", nft)
    got = fw.set_sizes()
    assert got == {"blocklist4": 3, "blocklist6": 0, "blockcidr4": 0, "blockcidr6": 0}


def test_set_sizes_empty_without_root(monkeypatch):
    from kevward import firewall as fw

    monkeypatch.setattr(fw, "nft_available", lambda: True)
    monkeypatch.setattr(fw, "is_root", lambda: False)
    assert fw.set_sizes() == {}


def test_report_shows_entry_counts():
    html = render(_res({
        "firewall": {"blocklist4": [4, 172], "blockcidr4": [5, 260]},
        "firewall_sizes": {"blocklist4": 51, "blocklist6": 0,
                           "blockcidr4": 1, "blockcidr6": 0},
    }))
    assert ("evidence blocklist <b>4</b> packets <span style='font-size:12px'>(51 entries)"
            "</span>") in html
    assert ("operator CIDR blocks <b>5</b> packets <span style='font-size:12px'>(1 entry)"
            "</span>") in html


def test_report_without_sizes_unchanged():
    html = render(_res({"firewall": {"blocklist4": [4, 172]}}))
    assert "evidence blocklist <b>4</b> packets · " in html
    assert "entries)" not in html


def test_japanese_units_on_both_numbers():
    from kevward.reporting.i18n import translator
    t = translator("ja")
    assert t("({n} entries)", n="85") == "（登録 85 件）"
    line = t("firewall drops <span style='font-size:12px'>({window})</span>: evidence "
             "blocklist <b>{evidence}</b> packets{evidence_size} · operator CIDR blocks "
             "<b>{cidr}</b> packets{cidr_size} · total <b>{total}</b> packets",
             window="w", evidence="60", evidence_size="（登録 85 件）", cidr="0",
             cidr_size="（登録 0 件）", total="60")
    assert "証拠ブロックリスト <b>60</b> パケット（登録 85 件）" in line
    assert "運用者の CIDR ブロック <b>0</b> パケット（登録 0 件）" in line
