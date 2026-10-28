"""Self-contained HTML report: patch posture + attacker-IP visualization.

No external assets or JS frameworks — a single file you can scp off the box or
serve read-only. Renders in both light and dark.
"""

from __future__ import annotations

import html
from datetime import datetime

from ..engine import RunResult

_SEV_COLOR = {
    "critical": "#b4232a",
    "high": "#c0582b",
    "medium": "#b8860b",
    "low": "#2f6f4f",
    "info": "#50607a",
}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _bar(label: str, value: int, maximum: int, color: str) -> str:
    pct = 0 if maximum == 0 else round(100 * value / maximum)
    return (
        f'<div class="row"><span class="lbl" title="{_esc(label)}">{_esc(label)}</span>'
        f'<span class="track"><span class="fill" style="width:{pct}%;'
        f'background:{color}"></span></span>'
        f'<span class="val">{value}</span></div>'
    )


def render(result: RunResult) -> str:
    att = result.attackers or {}
    f2b = att.get("fail2ban", {})
    lw = att.get("logwatch", {})
    trends = att.get("trends", {})

    # --- findings table ---
    sev_counts: dict[str, int] = {}
    rows = []
    for svc in result.services:
        if not svc.present:
            continue
        for f in svc.findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            kind = f.kind if isinstance(f.kind, str) else f.kind.value
            rows.append(
                f"<tr><td><span class='pill' style='background:{_SEV_COLOR.get(sev,'#777')}'>"
                f"{_esc(sev)}</span></td><td>{_esc(f.service)}</td>"
                f"<td>{_esc(kind)}</td><td>{_esc(f.title)}</td>"
                f"<td class='cve'>{_esc(f.cve or '')}</td></tr>"
            )

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

    # --- trend matches ---
    trend_rows = ""
    for m in (trends.get("matches") or [])[:30]:
        rw = " \U0001F512" if m.get("ransomware") else ""
        trend_rows += (
            f"<tr><td class='cve'>{_esc(m.get('cve'))}{rw}</td>"
            f"<td>{_esc(m.get('vendor'))}/{_esc(m.get('product'))}</td>"
            f"<td>{_esc(m.get('name'))}</td>"
            f"<td>{_esc(m.get('date_added'))}</td></tr>"
        )
    trend_block = ""
    if trends:
        trend_block = f"""
        <section>
          <h2>Actively-exploited (CISA KEV) relevant to this host</h2>
          <p class="muted">Catalog: {trends.get('catalog_size','?')} CVEs ·
          matches: <b>{trends.get('match_count',0)}</b> ·
          ransomware-linked: <b>{trends.get('ransomware_linked',0)}</b>
          {'· (cached snapshot)' if not trends.get('cache_fresh') else ''}</p>
          <p class="muted" style="font-size:12px">Matched by product name against
          software detected on this host. This flags <em>possible</em> exposure —
          confirm version-level applicability for each CVE before acting.</p>
          <table><thead><tr><th>CVE</th><th>Vendor/Product</th>
          <th>Name</th><th>Added</th></tr></thead>
          <tbody>{trend_rows or "<tr><td colspan=4 class='muted'>No matches.</td></tr>"}</tbody></table>
        </section>"""

    generated = _esc(result.generated_at)
    reboot = "YES" if result.reboot_required else "no"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
    <p class="muted">{_esc(result.os)} · generated {generated} · reboot required: <b>{reboot}</b></p>
    <div class="chips">{chip('critical')}{chip('high')}{chip('medium')}{chip('low')}{chip('info')}</div>
  </header>

  {trend_block}

  <section>
    <h2>Findings</h2>
    <table><thead><tr><th>Sev</th><th>Service</th><th>Kind</th><th>Title</th><th>CVE</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan=5 class='muted'>No findings.</td></tr>"}</tbody></table>
  </section>

  <section>
    <h2>Attack sources</h2>
    <div class="grid">
      <div>
        <p class="muted">fail2ban bans — currently banned: <span class="kpi">{f2b.get('live_total',0)}</span>
        · unique offenders seen: <b>{f2b.get('unique_ips',0)}</b></p>
        {ban_bars}
      </div>
      <div>
        <p class="muted">sshd auth failures — sources: <b>{lw.get('ssh_unique_sources',0)}</b>
        · attempts: <b>{lw.get('ssh_total_attempts',0)}</b></p>
        {ssh_bars}
      </div>
    </div>
  </section>

  <footer class="muted" style="text-align:center;font-size:12px">
    kevward · defensive posture report · {datetime.now().year} ·
    AGPL-3.0 ·
    <a href="https://github.com/ForexRobotics/kevward" style="color:inherit">source</a>
  </footer>
</div></body></html>"""
