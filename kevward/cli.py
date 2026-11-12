# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""kevward command-line interface.

Subcommands:
  check            Report findings (no changes). Default if none given.
  plan             Alias for check, framed as "what apply would do".
  apply            Apply security updates (and minor upgrades if policy allows).
  report           Write an HTML posture report (+ attacker IPs, + trends, + audit).
  trends           Show actively-exploited CVEs (CISA KEV) relevant to this host.
  schedule-reboot  Schedule a reboot in the maintenance window.
  firewall         Manage an nftables blocklist of attacker IPs (local host).
  harden           Host hardening checks + reversible interim mitigations.
  audit            Read-only scan for host compromise indicators (local host).
  list-plugins     Show discovered service plugins.

Safety: `apply` changes the system and is never implied. Everything else is
read-only. Reboots require both --reboot/`schedule-reboot` AND policy opt-in.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .engine import run as run_engine
from .integrations import fail2ban, logwatch
from .model import Severity
from .plugin import detected_kev_terms, discover
from .util import have, is_root


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", help="path to config.toml")
    p.add_argument("-s", "--service", action="append", dest="services",
                   help="limit to this service (repeatable)")
    p.add_argument("--json", action="store_true", help="emit JSON")


def _mkconfig(args, side_effects: bool = False) -> Config:
    """Load config. A broken file never crashes the CLI (#104): read-only
    commands warn and continue on defaults; side-effecting ones refuse, since
    defaults could change what they do (e.g. drop a firewall allowlist)."""
    cfg = Config.load(getattr(args, "config", None))
    if cfg.load_error:
        msg = f"config {cfg.source}: {cfg.load_error}"
        if side_effects:
            print(f"refused: {msg}\nfix the file before running this command.",
                  file=sys.stderr)
            raise SystemExit(2)
        print(f"warning: {msg} — running with built-in defaults", file=sys.stderr)
    if getattr(args, "services", None):
        cfg.policy.services = args.services
    return cfg


def _trends_kwargs(cfg: Config) -> dict:
    return {
        "version_budget_s": cfg.trends.version_budget_s,
        "max_version_checks": cfg.trends.max_version_checks,
    }


def _collect_attackers(include_trends: bool, host_terms=None, cfg: Config | None = None) -> dict:
    from . import firewall
    data = {
        "fail2ban": fail2ban.collect(),
        "logwatch": logwatch.collect(),
        "firewall": {k: list(v) for k, v in firewall.drop_counters().items()},
        "firewall_state": firewall.table_state(),
    }
    if include_trends:
        from .integrations import trends as trends_mod
        data["trends"] = trends_mod.matching_trends(
            host_terms, **_trends_kwargs(cfg or Config())
        )
    return data


def _print_findings(result, use_json: bool) -> int:
    if use_json:
        print(result.to_json())
    else:
        worst = Severity.INFO
        for svc in result.services:
            if not svc.present:
                continue
            head = f"[{svc.service}]"
            if svc.version:
                head += f" {svc.version}"
            print(head)
            if svc.error:
                print(f"  ! error: {svc.error}")
            for f in svc.findings:
                sev = f.severity if isinstance(f.severity, str) else f.severity.value
                print(f"  - {sev.upper():8} {f.title}")
                if f.severity.rank > worst.rank:
                    worst = f.severity
            if not svc.findings:
                print("  ok")
        if result.reboot_status == "now":
            print("\n** reboot required **")
        elif result.reboot_status == "after-updates":
            print("\n** reboot needed after applying pending updates **")
    # exit code reflects worst severity for CI/cron use
    return 0


def cmd_check(args) -> int:
    cfg = _mkconfig(args)
    result = run_engine(cfg, do_apply=False, dry_run=True)
    return _print_findings(result, args.json)


def cmd_apply(args) -> int:
    cfg = _mkconfig(args, side_effects=args.yes)
    if args.minor:
        cfg.policy.apply_minor = True
    dry = not args.yes
    if dry:
        print("DRY RUN (pass --yes to actually apply)")
        if not is_root() and have("apt-get"):
            print("note: not root — apt package lists were not refreshed; "
                  "run with sudo for an up-to-date plan")
        print()
    result = run_engine(cfg, do_apply=True, dry_run=dry)
    failed = False
    for svc in result.services:
        for a in svc.actions:
            tag = "would" if a.dry_run else ("ok" if a.ok else "FAIL")
            line = f"[{svc.service}] {tag}: {a.description}"
            if not a.ok and not a.dry_run and a.output:
                # Surface why it failed (e.g. "requires root -- re-run with sudo").
                reason = a.output.strip().splitlines()[0][:200]
                line += f"  ({reason})"
                failed = True
            print(line)
    if result.reboot_required:
        if cfg.policy.allow_reboot and args.reboot and not dry:
            from .scheduler import schedule_reboot
            print(schedule_reboot(cfg.policy.reboot_window_start))
        else:
            print("\nreboot required (not scheduled; use schedule-reboot or --reboot "
                  "with allow_reboot=true)")
    return 1 if failed else 0


def _write_last_run(report_dir: Path, record: dict) -> None:
    """Best-effort ``last-run.json`` beside the report (#106). Never raises."""
    import json

    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        tmp = report_dir / ".last-run.json.tmp"
        tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(report_dir / "last-run.json")
    except OSError:
        pass


def cmd_report(args) -> int:
    """Write the HTML report, plus ``last-run.json`` recording success or the
    one-line failure, so a collector can tell a fresh report from a stale one
    left behind by a failed run (#106)."""
    import socket
    from datetime import datetime, timezone

    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    record = {"started_at": _now(), "host": socket.gethostname(),
              "kevward_version": __version__}
    if args.output:
        report_dir = Path(args.output).parent
    else:
        try:
            report_dir = Config.load(getattr(args, "config", None)).report_dir
        except Exception:
            report_dir = Config().report_dir
    try:
        out = _cmd_report(args)
    except BaseException as exc:
        if isinstance(exc, SystemExit) and not exc.code:
            raise
        err = f"{type(exc).__name__}: {exc}".splitlines()[0][:300]
        record.update(finished_at=_now(), ok=False, error=err, report=None)
        _write_last_run(report_dir, record)
        raise
    record.update(finished_at=_now(), ok=True, error=None, report=str(out))
    _write_last_run(out.parent, record)
    return 0


def _cmd_report(args) -> Path:
    cfg = _mkconfig(args)
    result = run_engine(cfg, do_apply=False, dry_run=True)
    host_terms = detected_kev_terms(cfg.policy.services or None)
    result.attackers = _collect_attackers(args.trends, host_terms, cfg)
    if cfg.update.check:
        try:
            from .integrations.update_check import update_findings
            from .model import ServiceReport

            upd = update_findings()
            if upd:
                result.services.append(ServiceReport(
                    service="kevward", present=True, version=upd[0].current_version,
                    findings=upd))
        except Exception:
            pass  # a version notice must never break a report
    if args.audit:
        from . import audit as ad
        result.audit = ad.audit(cfg.audit.allowed_forced_commands)
    from .reporting.html import render
    out = Path(args.output) if args.output else cfg.report_dir / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(result), encoding="utf-8")
    if args.json:
        # keep stdout pure JSON so `report --json > posture.json` is valid (#113)
        print(f"wrote {out}", file=sys.stderr)
        print(result.to_json())
    else:
        print(f"wrote {out}")
    return out


def cmd_trends(args) -> int:
    cfg = _mkconfig(args)
    from .integrations import trends as trends_mod
    host_terms = detected_kev_terms(cfg.policy.services or None)
    data = trends_mod.matching_trends(host_terms, **_trends_kwargs(cfg))
    data["kevward_version"] = __version__
    if args.json:
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    print(f"CISA KEV catalog: {data['catalog_size']} CVEs "
          f"({'fresh' if data['cache_fresh'] else 'cached'})")
    print(f"matched to detected software ({', '.join(host_terms)}): "
          f"{data['match_count']} ({data['ransomware_linked']} ransomware-linked)")
    if data.get("version_aware"):
        print(f"version-checked: {data.get('applicable_count', 0)} applicable here, "
              f"{data.get('fixed_count', 0)} already fixed, "
              f"{data.get('unchecked_count', 0)} not checked, "
              f"{data.get('not_applicable_count', 0)} n/a by host config, "
              f"{data.get('na_release_count', 0)} n/a for this release "
              f"(rest: version not confirmed)")
        cc = data.get("cve_cache") or {}
        if cc and not cc.get("writable", True):
            print(f"warning: CVE cache not writable ({cc.get('dir')}) — run as "
                  "root or set XDG_CACHE_HOME; 'not checked' CVEs will not resolve")
        elif cc.get("fallback"):
            print(f"note: using per-user CVE cache {cc.get('dir')} "
                  "(system cache is root-only)")
        print()
    else:
        print("note: name-level match — confirm version applicability per CVE.\n")
    limit = 25
    for m in data["matches"][:limit]:
        rw = " [ransomware]" if m["ransomware"] else ""
        tag = f"[{m['applicability']}] " if data.get("version_aware") else ""
        print(f"  {tag}{m['cve']:18} {m['vendor']}/{m['product']}  "
              f"(added {m['date_added']}){rw}")
        if m.get("applicability_reason"):
            print(f"      n/a on this host: {m['applicability_reason']}")
    rest = len(data["matches"]) - limit
    if rest > 0:
        print(f"  ... and {rest} more (all matches: `kevward trends --json` "
              f"or the HTML report)")
    return 0


def cmd_schedule_reboot(args) -> int:
    cfg = _mkconfig(args, side_effects=True)
    if not cfg.policy.allow_reboot:
        print("refused: policy.allow_reboot is false. Set it to true to permit reboots.")
        return 2
    from .scheduler import schedule_reboot
    print(schedule_reboot(args.window or cfg.policy.reboot_window_start))
    return 0


def cmd_firewall(args) -> int:
    cfg = _mkconfig(args, side_effects=args.action in ("apply", "flush") and args.yes)
    from . import firewall as fw
    ttl_days = cfg.firewall.ttl_days
    if args.ttl:
        try:
            ttl_days = fw.parse_duration_days(args.ttl)
        except ValueError as e:
            print(f"error: {e}")
            return 2
    min_sshd = (args.min_sshd if args.min_sshd is not None
                else cfg.firewall.min_sshd_failures)
    extra_allow = list(cfg.firewall.allow) + (args.allow or [])
    block = list(cfg.firewall.block) + (args.block or [])
    persist = cfg.firewall.persist and not args.no_persist
    top_n = args.dnsbl_top_n if args.dnsbl_top_n is not None else cfg.firewall.dnsbl_top_n
    return fw.run_cli(
        args.action, ttl_days=ttl_days, min_sshd=min_sshd,
        extra_allow=extra_allow, yes=args.yes, use_json=args.json,
        block=block, persist=persist,
        check_dnsbl=args.check_dnsbl or cfg.firewall.check_dnsbl,
        require_reputation=args.require_reputation,
        dnsbl_zone=args.dnsbl_zone or cfg.firewall.dnsbl_zone,
        dnsbl_resolver=args.dnsbl_resolver or cfg.firewall.dnsbl_resolver,
        dnsbl_top_n=top_n, dnsbl_cache_days=cfg.firewall.dnsbl_cache_days,
    )


def cmd_harden(args) -> int:
    from . import harden as hd
    return hd.run_cli(
        args.action,
        mptcp_off=args.mptcp_off,
        drop_ip_options=args.drop_ip_options,
        persist=not args.no_persist,
        yes=args.yes,
        use_json=args.json,
    )


def cmd_audit(args) -> int:
    from . import audit as ad
    cfg = _mkconfig(args)
    return ad.run_cli(use_json=args.json,
                      allow_forced=cfg.audit.allowed_forced_commands)


def cmd_list_plugins(args) -> int:
    for name, cls in sorted(discover().items()):
        mode = "report-only" if not cls.supports_apply else "apply-capable"
        print(f"  {name:12} {mode}  ({cls.__module__})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kevward", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=f"kevward {__version__}")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="report findings (no changes)")
    _add_common(c)
    c.set_defaults(func=cmd_check)

    pl = sub.add_parser("plan", help="alias of check")
    _add_common(pl)
    pl.set_defaults(func=cmd_check)

    a = sub.add_parser("apply", help="apply security updates")
    _add_common(a)
    a.add_argument("--yes", action="store_true", help="actually apply (else dry-run)")
    a.add_argument("--minor", action="store_true", help="also apply minor upgrades")
    a.add_argument("--reboot", action="store_true", help="schedule reboot if required")
    a.set_defaults(func=cmd_apply)

    r = sub.add_parser("report", help="write HTML posture report")
    _add_common(r)
    r.add_argument("-o", "--output", help="output HTML path")
    r.add_argument("--trends", action="store_true", help="include CISA KEV trends (network)")
    r.add_argument("--audit", action="store_true",
                   help="include host compromise indicators (read-only; sudo for full view)")
    r.set_defaults(func=cmd_report)

    t = sub.add_parser("trends", help="actively-exploited CVEs relevant to host")
    _add_common(t)
    t.set_defaults(func=cmd_trends)

    sr = sub.add_parser("schedule-reboot", help="schedule a maintenance-window reboot")
    _add_common(sr)
    sr.add_argument("--window", help="HH:MM local time")
    sr.set_defaults(func=cmd_schedule_reboot)

    fw = sub.add_parser(
        "firewall",
        help="manage the active-defense blocklist (nftables, local host only)",
    )
    _add_common(fw)
    fw.add_argument("action", choices=["plan", "apply", "list", "flush"],
                    help="plan (dry run) / apply / list / flush kevward's set")
    fw.add_argument("--yes", action="store_true",
                    help="actually change the firewall (apply/flush)")
    fw.add_argument("--ttl", help="element TTL, e.g. 14d, 72h (default from config)")
    fw.add_argument("--min-sshd-failures", type=int, dest="min_sshd",
                    help="sshd-failure threshold to qualify an IP")
    fw.add_argument("--allow", action="append", dest="allow",
                    help="extra allowlisted CIDR/IP, never blocked (repeatable)")
    fw.add_argument("--block", action="append", dest="block",
                    help="permanent blocked CIDR/IP, no TTL (repeatable)")
    fw.add_argument("--no-persist", action="store_true", dest="no_persist",
                    help="don't install the boot-time re-apply systemd unit")
    fw.add_argument("--check-dnsbl", action="store_true", dest="check_dnsbl",
                    help="cross-check top candidates against a DNSBL (opt-in, network)")
    fw.add_argument("--require-reputation", action="store_true",
                    dest="require_reputation",
                    help="confirm mode: block only IPs the DNSBL flags as malicious")
    fw.add_argument("--dnsbl-zone", dest="dnsbl_zone",
                    help="DNSBL zone (e.g. a Spamhaus DQS zone)")
    fw.add_argument("--dnsbl-resolver", dest="dnsbl_resolver",
                    help="resolver IP to query directly (avoids public-resolver blocks)")
    fw.add_argument("--dnsbl-top-n", type=int, dest="dnsbl_top_n",
                    help="how many top candidates to look up (default 10)")
    fw.set_defaults(func=cmd_firewall)

    hd = sub.add_parser(
        "harden",
        help="host hardening: checks + reversible interim mitigations (local host)",
    )
    _add_common(hd)
    hd.add_argument("action", choices=["check", "plan", "apply", "list", "revert"],
                    help="check (read-only) / plan / apply / list / revert")
    hd.add_argument("--yes", action="store_true", help="actually apply/revert")
    hd.add_argument("--mptcp-off", action="store_true", dest="mptcp_off",
                    help="disable MPTCP kernel-wide (sysctl drop-in)")
    hd.add_argument("--drop-ip-options", action="store_true", dest="drop_ip_options",
                    help="drop inbound IPv4 packets with IP options (nftables)")
    hd.add_argument("--no-persist", action="store_true", dest="no_persist",
                    help="don't install the boot-time re-apply systemd unit")
    hd.set_defaults(func=cmd_harden)

    au = sub.add_parser(
        "audit",
        help="read-only scan for host compromise indicators (local host only)",
    )
    _add_common(au)
    au.set_defaults(func=cmd_audit)

    lp = sub.add_parser("list-plugins", help="list discovered plugins")
    _add_common(lp)
    lp.set_defaults(func=cmd_list_plugins)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        args = parser.parse_args((argv or []) + ["check"])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
