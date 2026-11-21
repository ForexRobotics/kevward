# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#180: the report frame in Japanese; English unchanged by default."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from kevward import cli
from kevward.config import Config
from kevward.engine import RunResult
from kevward.model import Finding, FindingKind, ServiceReport, Severity
from kevward.reporting import html as H
from kevward.reporting.i18n import JA, normalize, translator

HTML_SRC = Path(H.__file__).read_text()

# Messages passed to t() through a variable rather than a literal.
INDIRECT = [
    "critical", "high", "medium", "low", "info",
    "security_update", "minor_upgrade", "config", "vulnerability",
    "applicable", "fixed", "possible", "unchecked", "n/a (config)", "n/a (release)",
    "YES", "no", "after pending updates", "none", "unknown",
    "({n} entry)", "({n} entries)", "n/a on this host", "why",
    "No package or config findings (audit indicators are listed below).", "No findings.",
    "{line} — matched <code>[audit] allowed_outbound</code>",
    "{line} — configured in <code>[audit] allowed_outbound</code>",
    H._AUDIT_INTRO,
]


def _literal_messages() -> set[str]:
    """First-argument string literals of every t(...) call in html.py."""
    out: set[str] = set()
    for node in ast.walk(ast.parse(HTML_SRC)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "t" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.add(arg.value)
            elif isinstance(arg, ast.IfExp):
                for side in (arg.body, arg.orelse):
                    if isinstance(side, ast.Constant):
                        out.add(side.value)
    return out


def test_every_message_has_a_japanese_entry():
    msgs = _literal_messages() | set(INDIRECT)
    assert len(msgs) > 60
    missing = sorted(m for m in msgs if m not in JA)
    assert not missing, missing


def test_catalog_has_no_stale_entries_and_same_placeholders():
    import string
    used = _literal_messages() | set(INDIRECT)
    assert sorted(set(JA) - used) == []
    fields = lambda s: {f for _, f, _, _ in string.Formatter().parse(s) if f}  # noqa: E731
    for en, ja in JA.items():
        # {s} is the English plural suffix; Japanese has none.
        assert fields(ja) <= fields(en) and fields(en) - {"s"} <= fields(ja), en


def test_normalize():
    assert normalize(None) == "en" and normalize("") == "en"
    assert normalize("ja_JP.UTF-8") == "ja" and normalize("JA") == "ja"
    with pytest.raises(ValueError):
        normalize("fr")
    assert translator("en")("No findings.") == "No findings."
    assert translator("ja")("No findings.") == "指摘はありません。"
    assert translator("ja")("not in catalog {x}", x=1) == "not in catalog 1"


def _result():
    r = RunResult(host="tk2-225", generated_at="2026-11-21T00:00:00+00:00", os="Linux")
    f = Finding(service="apt", kind=FindingKind.SECURITY_UPDATE, severity=Severity.HIGH,
                title="php8.3 8.3.36 → 8.3.37", ref="php8.3",
                url="https://www.php.net/releases/8_3_37.php", fixed_version="8.3.37-2",
                packages=["php8.3"], package_versions={"php8.3": "8.3.36-1"},
                updated_packages=["php8.3-fpm"], source_package="php8.3")
    r.services = [ServiceReport("apt", True, findings=[f])]
    r.audit = []
    return r


def test_japanese_frame_keeps_finding_text():
    out = H.render(_result(), lang="ja")
    assert '<html lang="ja">' in out
    assert "<h2>指摘</h2>" in out and "侵入の痕跡（audit）" in out
    assert ">高</span>" in out and "<td class='kind'>セキュリティ更新</td>" in out
    assert "php8.3 8.3.36 → 8.3.37" in out  # plugin text unchanged
    assert "未更新: php8.3 8.3.36-1" in out
    assert "同じソース（php8.3）の他の 1 パッケージは 8.3.37-2 に更新済み" in out
    assert ">アドバイザリ</a>" in out
    assert "Noto Sans JP" in out
    assert "<h2>Findings</h2>" not in out


def test_english_default_unchanged():
    out = H.render(_result())
    assert '<html lang="en">' in out and "<h2>Findings</h2>" in out
    assert "still old: php8.3 8.3.36-1 · 1 other php8.3 package already at 8.3.37-2" in out
    assert "Noto Sans JP" not in out
    assert out == H.render(_result(), lang="en")


def test_config_and_cli(tmp_path, monkeypatch):
    p = tmp_path / "c.toml"
    p.write_text('[report]\nlang = "ja"\n')
    assert Config.load(p).report.lang == "ja"
    p.write_text('[report]\nlang = "fr"\n')
    assert Config.load(p).load_error  # unknown language: config error, defaults
    assert Config().report.lang == "en"

    seen = {}

    def fake_render(result, lang=None):
        seen["lang"] = lang
        return "<html></html>"

    import kevward.reporting.html as html_mod
    monkeypatch.setattr(html_mod, "render", fake_render)
    monkeypatch.setattr(cli, "run_engine", lambda *a, **k: RunResult("h", "t", "Linux"))
    monkeypatch.setattr(cli, "_collect_attackers", lambda *a, **k: {})
    out = tmp_path / "r.html"
    p.write_text('[report]\nlang = "ja"\n[update]\ncheck = false\n')
    cli.main(["report", "-c", str(p), "-o", str(out)])
    assert seen["lang"] == "ja"
    cli.main(["report", "-c", str(p), "-o", str(out), "--lang", "en"])
    assert seen["lang"] == "en"


def test_layout_logo_categories_and_summary():
    out = H.render(_result(), lang="ja")
    assert '<img class="logo" alt="kevward" src="data:image/png;base64,' in out
    assert '<div class="cat cat-own">このホストの状態</div>' in out
    assert '<div class="cat cat-atk">このホストへの攻撃</div>' in out
    assert '<div class="cat cat-ctx">侵入の痕跡</div>' in out  # audit ran ([] here)
    assert "<p class=\"status bad\">対応が必要な指摘（緊急・高）が 1 件あります。</p>" in out
    assert "<span class='chip act bad'>要対応（緊急・高）: <b>1</b></span>" in out
    r = RunResult(host="h", generated_at="t", os="Linux")
    en = H.render(r)
    assert ('<p class="status ok">No critical or high findings, and no actively-exploited '
            'CVE applies to this host.</p>') in en
    assert "cat-ctx" not in en.split("</style>", 1)[1]  # no audit run: no audit category
    r.attackers = {"trends": {"applicable_count": 2, "matches": []}}
    assert ("actively-exploited CVEs (CISA KEV) that apply to this host: 2."
            in H.render(r))
