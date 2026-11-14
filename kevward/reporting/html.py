# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Self-contained HTML report: patch posture + attacker-IP visualization.

No external assets or JS frameworks — a single file you can scp off the box or
serve read-only. Renders in both light and dark.
"""

from __future__ import annotations

import html
import re
from dataclasses import replace
from datetime import datetime

from .. import __version__ as _KW_VERSION
from ..engine import RunResult
from ..util import format_pkgs

_SEV_COLOR = {
    "critical": "#b4232a",
    "high": "#c0582b",
    "medium": "#b8860b",
    "low": "#2f6f4f",
    "info": "#50607a",
}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _ssh_window(lw: dict) -> tuple[str, str]:
    """Label the sshd failure totals with the period they cover, and add the
    last-24h / 7-day slice, so an all-time total from rotated logs is not read
    as a current attack. Returns (suffix for the totals line, recent line)."""
    start, end = lw.get("ssh_window_start"), lw.get("ssh_window_end")
    if not lw.get("ssh_total_attempts") or not start:
        return "", ""
    span = f"{_esc(str(start)[:10])} → {_esc(str(end or start)[:10])}"
    suffix = (
        f" <span style='font-size:12px'>(all rotated auth logs, {span})</span>"
    )
    n24 = int(lw.get("ssh_attempts_24h") or 0)
    n7 = int(lw.get("ssh_attempts_7d") or 0)
    s24 = int(lw.get("ssh_sources_24h") or 0)
    recent = (
        f"<p class='muted' style='margin-top:-6px'>last 24h: <b>{n24:,}</b> "
        f"attempts from <b>{s24}</b> sources · last 7d: <b>{n7:,}</b></p>"
    )
    return suffix, recent


def _bar(label: str, value: int, maximum: int, color: str) -> str:
    pct = 0 if maximum == 0 else round(100 * value / maximum)
    return (
        f'<div class="row"><span class="lbl" title="{_esc(label)}">{_esc(label)}</span>'
        f'<span class="track"><span class="fill" style="width:{pct}%;'
        f'background:{color}"></span></span>'
        f'<span class="val">{value}</span></div>'
    )



def _fw_window(since, generated_at: str) -> str:
    """'since 2026-11-11 22:00 UTC, 9.3 h' for the drop counters' window, so
    hosts can be compared; falls back to the old wording when unknown."""
    import datetime as _dt
    try:
        start = _dt.datetime.fromtimestamp(int(since), tz=_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return "since last ruleset load"
    label = f"since {start:%Y-%m-%d %H:%M} UTC"
    try:
        now = _dt.datetime.fromisoformat(generated_at)
        hours = (now - start).total_seconds() / 3600
    except (TypeError, ValueError):
        return label
    if hours < 0:
        return label
    span = f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.1f} days"
    return f"{label}, {span}"

def _finding_extra(f) -> str:
    """Package list for grouped apt findings and a link to the advisories (#143)."""
    bits = []
    pkgs = getattr(f, "packages", None) or []
    if len(pkgs) > 1:
        bits.append(_esc(", ".join(pkgs)))
    url = getattr(f, "url", None)
    if url and url.startswith("https://"):
        bits.append(f"<a href='{_esc(url)}' rel='noopener'>advisories</a>")
    if not bits:
        return ""
    return "<br><span class='muted'>" + " · ".join(bits) + "</span>"


_PKG_KINDS = ("security_update", "minor_upgrade")


def _refs(f) -> list[str]:
    pkgs = getattr(f, "packages", None) or []
    return list(pkgs) if pkgs else ([f.ref] if f.ref else [])


def _pkg_keys(f) -> list[tuple]:
    """(package, new version) for each package a package-change finding covers."""
    kind = f.kind if isinstance(f.kind, str) else f.kind.value
    if kind not in _PKG_KINDS:
        return []
    return [(p, f.fixed_version) for p in _refs(f)]


def _service_pkg_keys(result: RunResult) -> set:
    """Package changes reported by a service plugin (anything but "apt")."""
    return {
        k
        for svc in result.services
        if svc.present and svc.service != "apt"
        for f in svc.findings
        for k in _pkg_keys(f)
    }


def _without_owned(f, owned: set):
    """An apt finding minus the packages a service plugin already lists.

    None when nothing is left. A grouped finding (#143) that loses only some
    packages keeps the rest, with its "(N packages)" count corrected."""
    keys = _pkg_keys(f)
    if not keys:
        return f
    left = [p for p, v in keys if (p, v) not in owned]
    if not left:
        return None
    if len(left) == len(keys) or not getattr(f, "packages", None):
        return f
    n = len(left)
    title = re.sub(r"\(\d+ packages\)", f"({n} package{'s' if n != 1 else ''})", f.title)
    return replace(f, packages=left, ref=left[0], title=title)


def render(result: RunResult) -> str:
    att = result.attackers or {}
    f2b = att.get("fail2ban", {})
    lw = att.get("logwatch", {})
    trends = att.get("trends", {})

    # --- findings table ---
    sev_counts: dict[str, int] = {}
    rows = []
    owned = _service_pkg_keys(result)
    hidden_dupes = 0
    for svc in result.services:
        if not svc.present:
            continue
        for f in svc.findings:
            if svc.service == "apt":
                # Same package change already listed under its service plugin
                # (e.g. apache2 under "apache"): show and count it once. A
                # grouped row keeps the packages no service plugin owns.
                trimmed = _without_owned(f, owned)
                if trimmed is None:
                    hidden_dupes += 1
                    continue
                f = trimmed
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            kind = f.kind if isinstance(f.kind, str) else f.kind.value
            rows.append(
                f"<tr><td><span class='pill' style='background:{_SEV_COLOR.get(sev,'#777')}'>"
                f"{_esc(sev)}</span></td><td>{_esc(f.service)}</td>"
                f"<td>{_esc(kind)}</td><td>{_esc(f.title)}{_finding_extra(f)}</td>"
                f"<td class='cve'>{_esc(f.cve or '')}</td></tr>"
            )

    # --- audit (host compromise indicators) ---
    audit_rows = ""
    for f in (result.audit or []):
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        sev_counts[sev] = sev_counts.get(sev, 0) + 1  # reflected in the header chips
        audit_rows += (
            f"<tr><td><span class='pill' style='background:{_SEV_COLOR.get(sev,'#777')}'>"
            f"{_esc(sev)}</span></td><td>{_esc(f.title)}</td>"
            f"<td class='muted'>{_esc(f.detail)}</td></tr>"
        )
    audit_block = ""
    # Shown only when `report --audit` ran: None means audit was not requested.
    if result.audit is not None:
        audit_block = f"""
  <section>
    <h2>Host compromise indicators (audit)</h2>
    <p class="muted" style="font-size:12px">Read-only scan for a post-intrusion
    foothold — reverse SSH / tunnels, reverse-shell or bind-backdoor sockets, and
    persistence (ld.so.preload, cron, systemd units, rc, authorized_keys). These
    flag <em>possible</em> indicators to review, not confirmed compromise; run as
    root for full visibility.</p>
    <table><thead><tr><th>Sev</th><th>Indicator</th><th>Detail</th></tr></thead>
    <tbody>{audit_rows or "<tr><td colspan=3 class='muted'>No compromise indicators found.</td></tr>"}</tbody></table>
  </section>"""

    # Audit indicators are counted in the chips too; say so, or a header of
    # "low: 1" next to an empty Findings table reads as a contradiction.
    n_audit = len(result.audit or [])
    audit_note = (
        f"<p class='muted' style='font-size:12px;margin:6px 0 0'>counts include "
        f"{n_audit} audit indicator{'s' if n_audit != 1 else ''} "
        f"(see Host compromise indicators)</p>" if n_audit else ""
    )
    dupe_note = (
        f"<p class='muted' style='font-size:12px;margin:0 0 6px'>{hidden_dupes} "
        f"apt row{'s' if hidden_dupes != 1 else ''} not repeated: the same package "
        f"update is listed under its service (counted once)</p>" if hidden_dupes else ""
    )
    no_findings = ("No package or config findings (audit indicators are listed "
                   "below)." if n_audit else "No findings.")

    def chip(sev: str) -> str:
        return (
            f"<span class='chip' style='border-color:{_SEV_COLOR[sev]};"
            f"color:{_SEV_COLOR[sev]}'>{sev}: "
            f"<b>{sev_counts.get(sev,0)}</b></span>"
        )

    # --- attacker bars ---
    offenders = f2b.get("top_offenders") or []
    ssh = lw.get("ssh_failed_logins") or []
    max_ban = max((c for _, c in offenders), default=0)
    max_ssh = max((c for _, c in ssh), default=0)
    ban_bars = "".join(
        _bar(ip, c, max_ban, "#c0582b") for ip, c in offenders[:20]
    ) or "<p class='muted'>No fail2ban history found.</p>"
    ssh_bars = "".join(
        _bar(ip, c, max_ssh, "#50607a") for ip, c in ssh[:20]
    ) or "<p class='muted'>No sshd auth failures found.</p>"

    ssh_window, ssh_recent = _ssh_window(lw)

    # --- firewall drops (issue #42 follow-up): packets dropped per kevward set.
    fw = att.get("firewall") or {}

    def _fw_pkts(*sets: str) -> int:
        return sum(int(fw[s][0]) for s in sets if s in fw)

    sizes = att.get("firewall_sizes") or {}

    def _fw_size(*sets: str) -> str:
        """' (51 entries)' when the set sizes are known, else ''."""
        if not any(s in sizes for s in sets):
            return ""
        n = sum(int(sizes.get(s, 0)) for s in sets)
        return (f" <span style='font-size:12px'>({n:,} "
                f"entr{'y' if n == 1 else 'ies'})</span>")

    fw_line = ""
    if fw:
        evidence = _fw_pkts("blocklist4", "blocklist6")
        cidr = _fw_pkts("blockcidr4", "blockcidr6")
        total = evidence + cidr
        fw_line = (
            "<p class='muted' style='margin-top:0'>firewall drops "
            f"<span style='font-size:12px'>({_fw_window(att.get('firewall_since'), result.generated_at)})</span>: "
            f"evidence blocklist <b>{evidence:,}</b>{_fw_size('blocklist4', 'blocklist6')} · "
            f"operator CIDR blocks <b>{cidr:,}</b>{_fw_size('blockcidr4', 'blockcidr6')} · "
            f"total <b>{total:,}</b> packets</p>"
        )

    # Blocklist meant to be on (boot unit enabled) but the table is gone.
    fw_state = att.get("firewall_state") or {}
    if fw_state.get("table") is False and fw_state.get("unit") == "enabled":
        fw_line += (
            "<p style='margin-top:0;color:#b4232a'><b>⚠ kevward firewall not "
            "loaded</b> — the boot unit is enabled but table <code>inet kevward"
            "</code> is absent, so no IPs are being blocked. Check "
            "<code>systemctl status kevward-firewall</code>, then run "
            "<code>kevward firewall apply --yes</code>.</p>"
        )

    # --- trend matches ---
    _va = bool(trends.get("version_aware"))
    _badge = {
        "applicable": ("applicable", "#c0582b"),
        "fixed": ("fixed", "#2f6f4f"),
        "possible": ("possible", "#50607a"),
        "unchecked": ("unchecked", "#b8860b"),
        "not_applicable": ("n/a (config)", "#2f6f4f"),
        "na_release": ("n/a (release)", "#2f6f4f"),
    }
    def _na_note(m: dict) -> str:
        r = m.get("applicability_reason")
        return f"<br><small>n/a on this host: {_esc(r)}</small>" if r else ""

    def _trend_row(m: dict) -> str:
        rw = " \U0001F512" if m.get("ransomware") else ""
        status_cell = ""
        if _va:
            label, color = _badge.get(m.get("applicability", "possible"), _badge["possible"])
            status_cell = f"<td><span class='pill' style='background:{color}'>{label}</span></td>"
        return (
            f"<tr><td class='cve'>{_esc(m.get('cve'))}{rw}</td>"
            f"{status_cell}"
            f"<td>{_esc(m.get('vendor'))}/{_esc(m.get('product'))}</td>"
            f"<td>{_esc(m.get('name'))}{_na_note(m)}</td>"
            f"<td>{_esc(m.get('date_added'))}</td></tr>"
        )

    # Every match is listed: the table used to stop at 30 rows without saying
    # so, hiding e.g. 21 of 51 matches on a 22.04 host. Rows Ubuntu's release
    # data rules out (#74) are still listed, but in a collapsed table below so
    # decade-old kernel CVEs do not bury the rows that need a look.
    _all = trends.get("matches") or []
    trend_rows = "".join(
        _trend_row(m) for m in _all if m.get("applicability") != "na_release"
    )
    _na_rel = [m for m in _all if m.get("applicability") == "na_release"]
    trend_block = ""
    if trends:
        _status_th = "<th>Status</th>" if _va else ""
        _ncols = 5 if _va else 4
        if _va:
            applic_line = (
                f" · <b>{trends.get('applicable_count', 0)}</b> applicable here"
                f" · {trends.get('fixed_count', 0)} already fixed"
            )
            if trends.get("not_applicable_count"):
                applic_line += (
                    f" · {trends['not_applicable_count']} n/a by host config"
                )
            if trends.get("na_release_count"):
                applic_line += (
                    f" · {trends['na_release_count']} n/a for this release"
                )
            if trends.get("unchecked_count"):
                applic_line += (
                    f" · <b style='color:#b8860b'>{trends['unchecked_count']}"
                    "</b> not checked"
                )
            _cc = trends.get("cve_cache") or {}
            if _cc and not _cc.get("writable", True):
                applic_line += (
                    "<br><b style='color:#b8860b'>CVE cache not writable "
                    f"({_esc(_cc.get('dir', ''))})</b> — run as root or set "
                    "XDG_CACHE_HOME; 'not checked' CVEs will not resolve"
                )
            note = (
                "Name-matched against software on this host, then cross-checked "
                "against installed versions via Ubuntu security data: "
                "<b>applicable</b> = affected and not yet patched on this host, "
                "<b>fixed</b> = already at/after the fixed version, "
                "<b>possible</b> = looked up, but no installed package for this "
                "release to judge (treat as name-level only), "
                "<b>unchecked</b> = the lookup did not complete this run "
                "(network or time budget) — re-run to resolve, "
                "<b>n/a (config)</b> = exploitable only under a configuration "
                "this host does not have (reason shown), "
                "<b>n/a (release)</b> = Ubuntu's data shows it cannot affect "
                "this release, e.g. fixed upstream before this kernel series "
                "(reason shown; listed separately below)."
            )
        else:
            applic_line = ""
            note = (
                "Matched by product name against software detected on this host. "
                "This flags <em>possible</em> exposure — confirm version-level "
                "applicability for each CVE before acting."
            )
        _na_release_block = ""
        if _na_rel:
            _na_release_block = (
                f"<details style='margin-top:10px'><summary class='muted'>"
                f"{len(_na_rel)} n/a for this release (Ubuntu data)</summary>"
                f"<table><tbody>{''.join(_trend_row(m) for m in _na_rel)}"
                "</tbody></table></details>"
            )
        trend_block = f"""
        <section>
          <h2>Actively-exploited (CISA KEV) relevant to this host</h2>
          <p class="muted">Catalog: {trends.get('catalog_size','?')} CVEs ·
          matches: <b>{trends.get('match_count',0)}</b> ·
          ransomware-linked: <b>{trends.get('ransomware_linked',0)}</b>{applic_line}
          {'· (cached snapshot)' if not trends.get('cache_fresh') else ''}</p>
          <p class="muted" style="font-size:12px">{note}</p>
          <table><thead><tr><th>CVE</th>{_status_th}<th>Vendor/Product</th>
          <th>Name</th><th>Added</th></tr></thead>
          <tbody>{trend_rows or f"<tr><td colspan={_ncols} class='muted'>No matches.</td></tr>"}</tbody></table>
          {_na_release_block}
        </section>"""

    generated = _esc(result.generated_at)
    if getattr(result, "config_error", None):
        config_cell = (f"<b style='color:#c0392b'>config: {_esc(result.config_source)} "
                       "(UNREADABLE — using defaults)</b>")
    elif getattr(result, "config_source", None):
        config_cell = f"config: {_esc(result.config_source)}"
    else:
        config_cell = "config: defaults"
    reboot = {"now": "YES", "after-updates": "after pending updates"}.get(
        result.reboot_status, "no"
    )
    if result.reboot_status == "now" and result.reboot_packages:
        reboot += f" ({_esc(format_pkgs(result.reboot_packages))})"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="kevward-generated-at" content="{_esc(result.generated_at)}">
<meta name="kevward-version" content="{_esc(_KW_VERSION)}">
<meta name="kevward-host" content="{_esc(result.host)}">
<title>kevward report — {_esc(result.host)}</title>
<style>
  :root {{
    --bg:#f6f7f9; --card:#fff; --fg:#1c2330; --muted:#657086; --line:#e2e6ec;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme=light]) {{
      --bg:#0f141b; --card:#161d27; --fg:#e7ecf3; --muted:#8c99ac; --line:#273040;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 16px 64px; }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  .muted {{ color:var(--muted); }}
  section {{ background:var(--card); border:1px solid var(--line);
    border-radius:12px; padding:18px 20px; margin:18px 0; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.04em;
    color:var(--muted); margin:0 0 14px; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }}
  .chip {{ border:1px solid; border-radius:999px; padding:2px 10px; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
  th,td {{ text-align:left; padding:7px 8px; border-bottom:1px solid var(--line);
    vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; }}
  .pill {{ color:#fff; border-radius:6px; padding:1px 8px; font-size:12px; }}
  .cve {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }}
  .row {{ display:flex; align-items:center; gap:10px; margin:3px 0; }}
  .lbl {{ width:150px; font-family:ui-monospace,monospace; font-size:12.5px;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .track {{ flex:1; background:var(--line); border-radius:5px; height:12px; overflow:hidden; }}
  .fill {{ display:block; height:100%; }}
  .val {{ width:46px; text-align:right; font-variant-numeric:tabular-nums; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  @media (max-width:720px) {{ .grid {{ grid-template-columns:1fr; }} .lbl {{ width:110px; }} }}
  .kpi {{ font-size:28px; font-weight:700; }}
</style></head>
<body><div class="wrap">
  <header>
    <h1>kevward — {_esc(result.host)}</h1>
    <p class="muted">{_esc(result.os)} · generated {generated} · reboot required: <b>{reboot}</b> · kevward {_KW_VERSION} · {config_cell}</p>
    <div class="chips">{chip('critical')}{chip('high')}{chip('medium')}{chip('low')}{chip('info')}</div>
    {audit_note}
  </header>

  {trend_block}

  <section>
    <h2>Findings</h2>
    {dupe_note}
    <table><thead><tr><th>Sev</th><th>Service</th><th>Kind</th><th>Title</th><th>CVE</th></tr></thead>
    <tbody>{''.join(rows) or f"<tr><td colspan=5 class='muted'>{no_findings}</td></tr>"}</tbody></table>
  </section>

  <section>
    <h2>Attack sources</h2>
    {fw_line}
    <div class="grid">
      <div>
        <p class="muted">fail2ban bans — currently banned: <span class="kpi">{f2b.get('live_total',0)}</span>
        · unique offenders seen: <b>{f2b.get('unique_ips',0)}</b></p>
        {ban_bars}
      </div>
      <div>
        <p class="muted">sshd auth failures — sources: <b>{lw.get('ssh_unique_sources',0)}</b>
        · attempts: <b>{lw.get('ssh_total_attempts',0)}</b>{ssh_window}</p>
        {ssh_recent}
        {ssh_bars}
      </div>
    </div>
  </section>
  {audit_block}

  <footer class="muted" style="text-align:center;font-size:12px">
    kevward {_KW_VERSION} · defensive posture report · {datetime.now().year} ·
    AGPL-3.0 ·
    <a href="https://github.com/ForexRobotics/kevward" style="color:inherit">source</a>
  </footer>
</div></body></html>"""
