"""patchward command-line interface.

Subcommands:
  check            Report findings (no changes). Default if none given.
  plan             Alias for check, framed as "what apply would do".
  apply            Apply security updates (and minor upgrades if policy allows).
  report           Write an HTML posture report (+ attacker IPs, + trends).
  trends           Show actively-exploited CVEs (CISA KEV) relevant to this host.
  schedule-reboot  Schedule a reboot in the maintenance window.
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


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", help="path to config.toml")
    p.add_argument("-s", "--service", action="append", dest="services",
                   help="limit to this service (repeatable)")
    p.add_argument("--json", action="store_true", help="emit JSON")


def _mkconfig(args) -> Config:
    cfg = Config.load(getattr(args, "config", None))
    if getattr(args, "services", None):
        cfg.policy.services = args.services
    return cfg


def _collect_attackers(include_trends: bool, host_terms=None) -> dict:
    data = {
        "fail2ban": fail2ban.collect(),
        "logwatch": logwatch.collect(),
    }
    if include_trends:
        from .integrations import trends as trends_mod
        data["trends"] = trends_mod.matching_trends(host_terms)
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
        if result.reboot_required:
            print("\n** reboot required **")
    # exit code reflects worst severity for CI/cron use
    return 0


def cmd_check(args) -> int:
    cfg = _mkconfig(args)
    result = run_engine(cfg, do_apply=False, dry_run=True)
    return _print_findings(result, args.json)


def cmd_apply(args) -> int:
    cfg = _mkconfig(args)
    if args.minor:
        cfg.policy.apply_minor = True
    dry = not args.yes
    if dry:
        print("DRY RUN (pass --yes to actually apply)\n")
    result = run_engine(cfg, do_apply=True, dry_run=dry)
    for svc in result.services:
        for a in svc.actions:
            tag = "would" if a.dry_run else ("ok" if a.ok else "FAIL")
            print(f"[{svc.service}] {tag}: {a.description}")
    if result.reboot_required:
        if cfg.policy.allow_reboot and args.reboot and not dry:
            from .scheduler import schedule_reboot
            print(schedule_reboot(cfg.policy.reboot_window_start))
        else:
            print("\nreboot required (not scheduled; use schedule-reboot or --reboot "
                  "with allow_reboot=true)")
    return 0


def cmd_report(args) -> int:
    cfg = _mkconfig(args)
    result = run_engine(cfg, do_apply=False, dry_run=True)
    host_terms = detected_kev_terms(cfg.policy.services or None)
    result.attackers = _collect_attackers(args.trends, host_terms)
    from .reporting.html import render
    out = Path(args.output) if args.output else cfg.report_dir / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(result), encoding="utf-8")
    print(f"wrote {out}")
    if args.json:
        print(result.to_json())
    return 0


def cmd_trends(args) -> int:
    cfg = _mkconfig(args)
    from .integrations import trends as trends_mod
    host_terms = detected_kev_terms(cfg.policy.services or None)
    data = trends_mod.matching_trends(host_terms)
    if args.json:
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    print(f"CISA KEV catalog: {data['catalog_size']} CVEs "
          f"({'fresh' if data['cache_fresh'] else 'cached'})")
    print(f"matched to detected software ({', '.join(host_terms)}): "
          f"{data['match_count']} ({data['ransomware_linked']} ransomware-linked)")
    print("note: name-level match — confirm version applicability per CVE.\n")
    for m in data["matches"][:25]:
        rw = " [ransomware]" if m["ransomware"] else ""
        print(f"  {m['cve']:18} {m['vendor']}/{m['product']}  (added {m['date_added']}){rw}")
    return 0


def cmd_schedule_reboot(args) -> int:
    cfg = _mkconfig(args)
    if not cfg.policy.allow_reboot:
        print("refused: policy.allow_reboot is false. Set it to true to permit reboots.")
        return 2
    from .scheduler import schedule_reboot
    print(schedule_reboot(args.window or cfg.policy.reboot_window_start))
    return 0


def cmd_list_plugins(args) -> int:
    for name, cls in sorted(discover().items()):
        mode = "report-only" if not cls.supports_apply else "apply-capable"
        print(f"  {name:12} {mode}  ({cls.__module__})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="patchward", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=f"patchward {__version__}")
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
    r.set_defaults(func=cmd_report)

    t = sub.add_parser("trends", help="actively-exploited CVEs relevant to host")
    _add_common(t)
    t.set_defaults(func=cmd_trends)

    sr = sub.add_parser("schedule-reboot", help="schedule a maintenance-window reboot")
    _add_common(sr)
    sr.add_argument("--window", help="HH:MM local time")
    sr.set_defaults(func=cmd_schedule_reboot)

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
