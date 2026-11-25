# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Report languages (#180).

The HTML report's frame — headings, explanations, labels, summary lines — can
be rendered in another language with ``[report] lang`` or
``kevward report --lang``. Finding titles and details written by plugins stay
in English for now (phase 2), as do JSON and CLI output.

No gettext/.mo build step and no dependency: messages are keyed by their
English text (a ``str.format`` template), so the renderer stays readable and
anything missing from a catalog falls back to English. Values passed in are
already HTML-escaped by the caller; catalog text is trusted markup.
"""

from __future__ import annotations

from collections.abc import Callable

DEFAULT_LANG = "en"
SUPPORTED = ("en", "ja")

Translator = Callable[..., str]

JA: dict[str, str] = {
    # --- page / header ---
    "kevward report — {host}": "kevward レポート — {host}",
    "{os} · generated {generated}": "{os} · 生成 {generated}",
    "reboot required: <b>{reboot}</b> · {sched}": "再起動: <b>{reboot}</b> · {sched}",
    "kevward {version} · {config}": "kevward {version} · {config}",
    "YES": "必要",
    "no": "不要",
    "after pending updates": "保留中の更新を入れた後に必要",
    "reboot scheduled: <b>{when}</b>": "再起動の予約: <b>{when}</b>",
    "apt lists: <b>refresh FAILED</b>": "apt リスト: <b>更新に失敗</b>",
    "apt lists: <b>{when} UTC ({hours} h ago)</b>":
        "apt リスト: <b>{when} UTC（{hours} 時間前）</b>",
    "apt lists: {when} UTC ({hours} h ago)": "apt リスト: {when} UTC（{hours} 時間前）",
    "(previous report: {before}, {change})": "（前回のレポート: {before}、{change}）",
    "none": "なし",
    "unknown": "不明",
    "config: {source}": "設定: {source}",
    "config: {source} (UNREADABLE — using defaults)":
        "設定: {source}（読み込めません — 既定値で動作中）",
    "config: defaults": "設定: 既定値",
    "({n} ignored setting{s} — see findings)": "（無視された設定 {n} 件 — 指摘を参照）",
    "rules loaded: allowed_outbound {o} · allowed_forced_commands {f}":
        "読み込んだルール: allowed_outbound {o} 件 · allowed_forced_commands {f} 件",
    "counts include {n} audit indicator{s} (see Host compromise indicators)":
        "件数には audit の兆候 {n} 件を含みます（「侵入の痕跡」を参照）",
    "defensive posture report": "防御態勢レポート",
    "source": "ソース",
    # --- categories / summary (layout aligned with stille-hunter's report) ---
    "This host": "このホストの状態",
    "Attacks on this host": "このホストへの攻撃",
    "Signs of intrusion": "侵入の痕跡",
    "Summary": "サマリー",
    "{n} critical/high finding{s} to act on": "対応が必要な指摘（緊急・高）が {n} 件あります",
    "actively-exploited CVEs (CISA KEV) that apply to this host: {n}":
        "悪用中の脆弱性（CISA KEV）がこのホストに {n} 件該当します",
    "; ": "。",
    ".": "。",
    "No critical or high findings, and no actively-exploited CVE applies to this host.":
        "緊急・高の指摘はなく、このホストに該当する悪用中の脆弱性（CISA KEV）もありません。",
    "to act on (critical/high): <b>{n}</b>": "要対応（緊急・高）: <b>{n}</b>",
    # --- severities / kinds ---
    "critical": "緊急",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "情報",
    "security_update": "セキュリティ更新",
    "minor_upgrade": "マイナー更新",
    "config": "設定",
    "vulnerability": "脆弱性",
    # --- findings ---
    "Findings": "指摘",
    "Sev": "重要度",
    "Service": "サービス",
    "Kind": "種類",
    "Title": "内容",
    "{n} apt row{s} not repeated: the same package update is listed under its "
    "service (counted once)":
        "apt の {n} 行は省略しました: 同じパッケージの更新を各サービスの行に表示しています"
        "（1 件として集計）",
    "No package or config findings (audit indicators are listed below).":
        "パッケージや設定の指摘はありません（audit の兆候は下に表示）。",
    "No findings.": "指摘はありません。",
    "still old: {items}": "未更新: {items}",
    "+{n} more": "ほか {n} 件",
    "{n} other {src} package{s} already at {version}":
        "同じソース（{src}）の他の {n} パッケージは {version} に更新済み",
    "{n} other {src} package{s} already upgraded":
        "同じソース（{src}）の他の {n} パッケージは更新済み",
    "{n} other package{s} already at {version}":
        "他の {n} パッケージは {version} に更新済み",
    "{n} other package{s} already upgraded": "他の {n} パッケージは更新済み",
    "advisories": "アドバイザリ",
    # --- CISA KEV ---
    "Actively-exploited (CISA KEV) relevant to this host":
        "このホストに関係する悪用中の脆弱性（CISA KEV）",
    "Catalog: {size} CVEs · matches: <b>{matches}</b> · ransomware-linked: "
    "<b>{ransomware}</b>":
        "カタログ: {size} 件 · 一致: <b>{matches}</b> · ランサムウェア関連: "
        "<b>{ransomware}</b>",
    " · <b>{n}</b> applicable here": " · 該当 <b>{n}</b>",
    " · {n} already fixed": " · 修正済み {n}",
    " · {n} n/a by host config": " · 設定により対象外 {n}",
    " · {n} n/a for this release": " · このリリースは対象外 {n}",
    " · <b style='color:#b8860b'>{n}</b> not checked":
        " · 未確認 <b style='color:#b8860b'>{n}</b>",
    "<br><b style='color:#b8860b'>CVE cache not writable ({dir})</b> — run as root "
    "or set XDG_CACHE_HOME; 'not checked' CVEs will not resolve":
        "<br><b style='color:#b8860b'>CVE キャッシュに書き込めません（{dir}）</b> — "
        "root で実行するか XDG_CACHE_HOME を設定してください。未確認の CVE が解消しません",
    "· (cached snapshot)": "·（キャッシュのスナップショット）",
    "Name-matched against software on this host, then cross-checked against "
    "installed versions via Ubuntu security data: <b>applicable</b> = affected and "
    "not yet patched on this host, <b>fixed</b> = already at/after the fixed "
    "version, <b>possible</b> = looked up, but no installed package for this "
    "release to judge (treat as name-level only), <b>unchecked</b> = the lookup "
    "did not complete this run (network or time budget) — re-run to resolve, "
    "<b>n/a (config)</b> = exploitable only under a configuration this host does "
    "not have (reason shown), <b>n/a (release)</b> = Ubuntu's data shows it cannot "
    "affect this release, e.g. fixed upstream before this kernel series (reason "
    "shown; listed separately below).":
        "このホストのソフトウェアと名前で照合し、Ubuntu のセキュリティデータで"
        "インストール済みの版と突き合わせています。"
        "<b>該当</b> = 影響があり、このホストではまだ修正されていない。"
        "<b>修正済み</b> = 修正版かそれ以降の版になっている。"
        "<b>可能性あり</b> = 調べたが、このリリースで判断できるパッケージが入っていない"
        "（名前の一致だけとして扱う）。"
        "<b>未確認</b> = 今回は調べ終わらなかった（ネットワークか時間の制限）。"
        "もう一度実行すると解消します。"
        "<b>対象外（設定）</b> = このホストにない設定のときだけ悪用できる（理由を表示）。"
        "<b>対象外（リリース）</b> = Ubuntu のデータではこのリリースに影響しない。"
        "たとえば、このカーネル系列より前に上流で修正済み（理由を表示。下に別に表示）。",
    "Matched by product name against software detected on this host. This flags "
    "<em>possible</em> exposure — confirm version-level applicability for each "
    "CVE before acting.":
        "このホストで見つかったソフトウェアと製品名で照合しています。"
        "影響の<em>可能性</em>を示すだけなので、対応の前に CVE ごとに版で確かめてください。",
    "CVE": "CVE",
    "Status": "状態",
    "Vendor/Product": "ベンダー/製品",
    "Name": "名称",
    "Added": "追加日",
    "No matches.": "一致なし。",
    "{n} n/a for this release (Ubuntu data)":
        "このリリースは対象外: {n} 件（Ubuntu のデータ）",
    "applicable": "該当",
    "fixed": "修正済み",
    "possible": "可能性あり",
    "unchecked": "未確認",
    "n/a (config)": "対象外（設定）",
    "n/a (release)": "対象外（リリース）",
    "n/a on this host": "このホストは対象外",
    "why": "理由",
    # --- attack sources ---
    "Attack sources": "攻撃元",
    "firewall drops <span style='font-size:12px'>({window})</span>: evidence "
    "blocklist <b>{evidence}</b>{evidence_size} · operator CIDR blocks "
    "<b>{cidr}</b>{cidr_size} · total <b>{total}</b> packets":
        "ファイアウォールで破棄 <span style='font-size:12px'>（{window}）</span>: "
        "証拠ブロックリスト <b>{evidence}</b>{evidence_size} · 運用者の CIDR ブロック "
        "<b>{cidr}</b>{cidr_size} · 合計 <b>{total}</b> パケット",
    "({n} entry)": "（{n} 件）",
    "({n} entries)": "（{n} 件）",
    "since last ruleset load": "ルールセットの読み込み以降",
    "since {start} UTC": "{start} UTC 以降",
    "{label}, {span}": "{label}、{span}",
    "{n} h": "{n} 時間",
    "{n} days": "{n} 日",
    "<b>⚠ kevward firewall not loaded</b> — the blocklist is in use on this host but "
    "table <code>inet kevward</code> is absent, so no IPs are being blocked. Run "
    "<code>sudo kevward firewall apply --yes</code> (after a reinstall: "
    "<code>sudo kevward setup --restore</code>).":
        "<b>⚠ kevward のファイアウォールが読み込まれていません</b> — このホストでは遮断リストを"
        "使っていますが、テーブル <code>inet kevward</code> がないため、どの IP も"
        "遮断されていません。<code>sudo kevward firewall apply --yes</code> を実行してください"
        "（再インストールのあとなら <code>sudo kevward setup --restore</code>）。",
    "firewall drops: <b>not loaded</b>": "ファイアウォールで破棄: <b>読み込まれていません</b>",
    "fail2ban bans — currently banned: <span class=\"kpi\">{live}</span> · unique "
    "offenders seen: <b>{unique}</b>":
        "fail2ban の BAN — 現在 BAN 中: <span class=\"kpi\">{live}</span> · "
        "これまでの攻撃元: <b>{unique}</b>",
    "No fail2ban history found.": "fail2ban の履歴はありません。",
    "sshd auth failures — sources: <b>{sources}</b> · attempts: <b>{attempts}</b>":
        "sshd の認証失敗 — 送信元: <b>{sources}</b> · 試行: <b>{attempts}</b>",
    "No sshd auth failures found.": "sshd の認証失敗はありません。",
    "(all rotated auth logs, {span})": "（ローテート済みを含む全 auth ログ、{span}）",
    "last 24h: <b>{n24}</b> attempts from <b>{s24}</b> sources{vs} · last 7d: <b>{n7}</b>":
        "直近 24 時間: <b>{s24}</b> 件の送信元から <b>{n24}</b> 回{vs} · "
        "直近 7 日: <b>{n7}</b> 回",
    # --- audit ---
    "Host compromise indicators (audit)": "侵入の痕跡（audit）",
    "Read-only scan for a post-intrusion\n    foothold — reverse SSH / tunnels, "
    "reverse-shell or bind-backdoor sockets, and\n    persistence (ld.so.preload, "
    "cron, systemd units, rc, authorized_keys). These\n    flag <em>possible</em> "
    "indicators to review, not confirmed compromise; run as\n    root for full "
    "visibility.":
        "侵入後の足がかりを読み取りだけで調べています。逆向き SSH やトンネル、"
        "リバースシェルや待ち受け型バックドアのソケット、永続化"
        "（ld.so.preload、cron、systemd ユニット、rc、authorized_keys）が対象です。"
        "確認すべき<em>可能性のある</em>兆候を示すもので、侵入が確定したわけでは"
        "ありません。すべてを見るには root で実行してください。",
    "Indicator": "兆候",
    "Detail": "詳細",
    "No compromise indicators found.": "侵入の痕跡は見つかりませんでした。",
    "{line} — matched <code>[audit] allowed_outbound</code>":
        "{line} — <code>[audit] allowed_outbound</code> に一致",
    "{line} — configured in <code>[audit] allowed_outbound</code>":
        "{line} — <code>[audit] allowed_outbound</code> で設定済み",
    "{line} — matched <code>[audit] allowed_forced_commands</code>":
        "{line} — <code>[audit] allowed_forced_commands</code> に一致",
    "{line} — configured in <code>[audit] allowed_forced_commands</code>":
        "{line} — <code>[audit] allowed_forced_commands</code> で設定済み（一致なし）",
}

CATALOGS: dict[str, dict[str, str]] = {"ja": JA}

# Extra CSS font fallback per language (system fonts only; nothing fetched).
FONT_FALLBACK = {
    "ja": '"Hiragino Sans","Hiragino Kaku Gothic ProN","Yu Gothic UI","Noto Sans JP",'
          "Meiryo,",
}


def normalize(lang: str | None) -> str:
    """'ja_JP.UTF-8' / 'JA' -> 'ja'; unknown -> ValueError. None/'' -> default."""
    if not lang:
        return DEFAULT_LANG
    code = str(lang).strip().lower().replace("-", "_").split(".", 1)[0].split("_", 1)[0]
    if code not in SUPPORTED:
        raise ValueError(f"unsupported report language {lang!r} (use one of: "
                         f"{', '.join(SUPPORTED)})")
    return code


def translator(lang: str | None) -> Translator:
    """``t(msg, **values)``: the catalog's text for ``msg`` (or ``msg`` itself),
    formatted with ``values``. English is the identity, so default output is
    unchanged."""
    catalog = CATALOGS.get(normalize(lang), {})

    def t(msg: str, **values) -> str:
        text = catalog.get(msg, msg)
        return text.format(**values) if values else text

    return t
