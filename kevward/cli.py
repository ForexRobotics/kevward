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
  schedule         Install / inspect / remove the daily report timer.
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
    for w in cfg.warnings:
        print(f"warning: config {cfg.source}: {w}", file=sys.stderr)
    if getattr(args, "services", None):
        cfg.policy.services = args.services
    return cfg


def audit_rule_counts(cfg: Config) -> dict[str, int]:
    """Rules loaded for the audit exceptions (#186): "0" means none in effect."""
    return {"allowed_outbound": len(cfg.audit.allowed_outbound),
            "allowed_forced_commands": len(cfg.audit.allowed_forced_commands)}


def _trends_kwargs(cfg: Config) -> dict:
    return {
        "version_budget_s": cfg.trends.version_budget_s,
        "max_version_checks": cfg.trends.max_version_checks,
        "fetch_workers": cfg.trends.fetch_workers,
    }


#: `trends --warm-cache`: one long pass that fills the Ubuntu CVE cache so the
#: daily report (45s budget) starts warm on a new or long-idle host (#66).
WARM_BUDGET_S = 600.0
WARM_MAX_CHECKS = 1000


def _warm_cache(cfg: Config, host_terms) -> int:
    from .integrations import trends as trends_mod
    from .util import is_root
    kw = _trends_kwargs(cfg)
    kw.update(version_budget_s=WARM_BUDGET_S, max_version_checks=WARM_MAX_CHECKS)
    print(f"warming the Ubuntu CVE cache (up to {int(WARM_BUDGET_S)}s, "
          f"{kw['fetch_workers']} at a time) ...", flush=True)
    data = trends_mod.matching_trends(host_terms, **kw)
    cc = data.get("cve_cache") or {}
    if not data.get("version_aware"):
        print("version-aware pass did not run (no Ubuntu codename or dpkg data).")
        return 1
    print(f"KEV matches: {data['match_count']}; "
          f"still unchecked: {data.get('unchecked_count', 0)}; "
          f"cache: {cc.get('dir', '?')}")
    if cc and not cc.get("writable", True):
        print("warning: cache not writable — nothing was saved; run with sudo")
        return 1
    if cc.get("fallback") and not is_root():
        print("note: per-user cache; the root daily report uses /var/cache/kevward "
              "— run `sudo kevward trends --warm-cache` to warm that one")
    return 0 if not data.get("unchecked_count") else 1


def _collect_attackers(include_trends: bool, host_terms=None, cfg: Config | None = None) -> dict:
    from . import firewall
    data = {
        "fail2ban": fail2ban.collect(),
        "logwatch": logwatch.collect(),
        "firewall": {k: list(v) for k, v in firewall.drop_counters().items()},
        "firewall_state": firewall.table_state(),
        "firewall_since": firewall.counters_since(),
        "firewall_sizes": firewall.set_sizes(),
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
            why = ""
            if result.reboot_packages:
                from .util import format_pkgs
                why = f" ({format_pkgs(result.reboot_packages)})"
            print(f"\n** reboot required{why} **")
        elif result.reboot_status == "after-updates":
            print("\n** reboot needed after applying pending updates **")
    # exit code reflects worst severity for CI/cron use
    return 0


def cmd_check(args) -> int:
    cfg = _mkconfig(args)
    result = run_engine(cfg, do_apply=False, dry_run=True)
    return _print_findings(result, args.json)


def refresh_line(refresh: dict) -> tuple[str, bool]:
    """First line of an apply plan: was the apt plan computed on fresh lists?
    Returns (line, is_warning). Pure (#171)."""
    state = (refresh or {}).get("state")
    if state == "ok":
        return f"apt lists refreshed (apt-get update ok, {refresh.get('seconds', 0)}s)", False
    if state == "failed":
        return (f"WARNING: apt-get update failed ({refresh.get('error') or 'unknown error'}); "
                "the plan below may be stale"), True
    if state == "skipped":
        return ("note: not root — apt package lists were not refreshed; "
                "run with sudo for an up-to-date plan"), False
    return "", False


def _kind(f) -> str:
    return f.kind if isinstance(f.kind, str) else f.kind.value


def plan_tail(result, apply_minor: bool) -> tuple[list[str], bool]:
    """Lines after the per-service actions: an empty plan, minor upgrades left
    out, and why a reboot is mentioned. Returns (lines, a reboot is needed now
    or after this plan). Pure over a RunResult (#171)."""
    lines: list[str] = []
    planned = {p for s in result.services for a in s.actions
               for p in a.description.removeprefix("install: ").split(", ")
               if a.description.startswith("install: ")}
    if not any(s.actions for s in result.services):
        lines.append("nothing to apply (0 packages)")
    if not apply_minor:
        minor = {p for s in result.services for f in s.findings
                 if _kind(f) == "minor_upgrade" for p in f.refs} - planned
        if minor:
            n = len(minor)
            lines.append(f"{n} minor upgrade{'s' if n != 1 else ''} not included (use --minor)")
    rebooting = {p for s in result.services for f in s.findings if f.reboot_required
                 for p in f.refs if _needs_reboot(p)}
    now = sorted(rebooting & planned)
    later = sorted(rebooting - planned)
    if result.reboot_pending:
        why = ", ".join(result.reboot_packages) or "reboot-required.pkgs not available"
        lines.append(f"reboot: already required ({why})")
    elif now:
        lines.append(f"reboot: will be required after these updates ({', '.join(now)})")
    elif later:
        lines.append("reboot: will be required once pending updates not in this plan "
                     f"are installed ({', '.join(later)})")
    return lines, bool(result.reboot_pending or now)


def _apply_job(args) -> int:
    """`apply --yes --expect-plan H [--job ID] [--reboot-at T]` (#197): install
    only if the plan still hashes to H. Started by ssh-gate `apply.start`."""
    from . import gate_apply

    if not args.yes:
        print("kevward: --expect-plan/--job need --yes (use `kevward ssh-gate` op plan "
              "for a dry run)")
        return 2
    if args.minor or args.reboot:
        print("kevward: --minor/--reboot cannot be combined with --expect-plan: the plan "
              "and the reboot come from the host's policy and --reboot-at")
        return 2
    cfg = _mkconfig(args, side_effects=True)
    return gate_apply.run_job(cfg, expect=args.expect_plan, job_id=args.job,
                              reboot_at=args.reboot_at)


def _needs_reboot(pkg: str) -> bool:
    from .plugins._apt import change_needs_reboot

    return change_needs_reboot(pkg)


def cmd_apply(args) -> int:
    if getattr(args, "job", None) or getattr(args, "expect_plan", None):
        return _apply_job(args)
    cfg = _mkconfig(args, side_effects=args.yes)
    if args.minor:
        cfg.policy.apply_minor = True
    dry = not args.yes
    if dry:
        print("DRY RUN (pass --yes to actually apply)")
    result = run_engine(cfg, do_apply=True, dry_run=dry)
    failed = False
    line, warn = refresh_line(result.apt_refresh)
    if line:
        print(line)
    if warn:
        failed = True
    print()
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
    tail, reboot_now = plan_tail(result, cfg.policy.apply_minor)
    for line in tail:
        print(line)
    sched = result.reboot_schedule or {}
    if result.reboot_required:
        if sched.get("state") == "scheduled":
            print(f"reboot scheduled: {sched.get('at') or 'yes'}")
        elif cfg.policy.allow_reboot and args.reboot and not dry:
            from .scheduler import schedule_reboot
            ok, msg = schedule_reboot(cfg.policy.reboot_window_start)
            print(msg)
            if not ok:
                failed = True
        elif reboot_now:
            print("  (not scheduled; use schedule-reboot or --reboot with allow_reboot=true)")
    return 1 if failed else 0


def cmd_setup(args) -> int:
    from .setup import setup
    from .ssh_gate import GateError, dumps, fail, ok

    try:
        if args.restore:
            from .setup import restore
            data = restore(dry_run=args.dry_run)
        else:
            data = setup(console_user=args.console_user, read_key=args.read_key,
                         operate_key=args.operate_key, ssh_gate=args.ssh_gate,
                         timer=args.timer, fail2ban_ignore=args.fail2ban_ignore,
                         refresh=args.refresh, self_update=args.self_update,
                         allow_reboot=args.allow_reboot, dry_run=args.dry_run)
        resp = ok(data)
    except GateError as e:
        resp = fail(e.code, e.message)
    except Exception as e:  # never a traceback in --json mode
        resp = fail("internal", f"{type(e).__name__}: {e}")
    if args.json:
        sys.stdout.write(dumps(resp))
    elif resp["ok"]:
        d = resp["data"]
        print("DRY RUN (nothing written)" if d["dry_run"] else "kevward setup")
        for a in d["actions"]:
            verb = {"create": "would create" if d["dry_run"] else "created",
                    "update": "would update" if d["dry_run"] else "updated"}.get(
                a["action"], a["action"])
            print(f"  {verb:13} {a['kind']:16} {a['path']}")
            for ln in a.get("lines", []):
                print(f"      {ln}")
    else:
        print(f"error ({resp['code']}): {resp['error']}", file=sys.stderr)
    return 0 if resp["ok"] else 2


def cmd_uninstall(args) -> int:
    from .ssh_gate import GateError, dumps, fail, ok
    from .uninstall import uninstall

    try:
        resp = ok(uninstall(yes=args.yes, purge=args.purge,
                            remove_collector_keys=args.remove_collector_keys))
    except GateError as e:
        resp = fail(e.code, e.message)
    except Exception as e:  # never a traceback in --json mode
        resp = fail("internal", f"{type(e).__name__}: {e}")
    if args.json:
        sys.stdout.write(dumps(resp))
    elif resp["ok"]:
        d = resp["data"]
        print("DRY RUN (pass --yes to remove)" if d["dry_run"] else "kevward uninstall")
        verb = "would remove" if d["dry_run"] else "removed"
        for a in d["actions"]:
            extra = f" ({a['lines']} line(s))" if "lines" in a else ""
            print(f"  {verb} {a['kind']:16} {a['target']}{extra}")
        if not d["actions"]:
            print("  nothing to remove")
        for e in d.get("errors", []):
            print(f"  error: {e}", file=sys.stderr)
        if not d["purge"] and not d["dry_run"]:
            print("kept: /etc/kevward, /var/log/kevward, /var/lib/kevward "
                  "(use --purge to delete)")
    else:
        print(f"error ({resp['code']}): {resp['error']}", file=sys.stderr)
    return 0 if resp["ok"] and not resp["data"].get("errors") else 2


def cmd_ssh_gate(args) -> int:
    from .ssh_gate import main as gate_main

    return gate_main(args.role, args.config)


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


def _summary_counts(data_path: Path) -> dict | None:
    """The header counts for last-run.json (#211), from the report.json just
    written; None if it is not there."""
    import json

    try:
        summ = json.loads(data_path.read_text(encoding="utf-8"))["summary"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    kev = summ.get("kev") or {}
    return {**summ.get("counts", {}), "act_now": summ.get("act_now"),
            "kev_applicable": kev.get("applicable")}


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
    record["counts"] = _summary_counts(Path(out).with_suffix(".json"))
    _write_last_run(Path(out).parent, record)
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
        notes: dict = {}
        result.audit = ad.audit(cfg.audit.allowed_forced_commands,
                                cfg.audit.allowed_outbound, notes)
        result.audit_allowed_outbound = notes.get("allowed_outbound_hits") or {}
        result.audit_allowed_forced = notes.get("allowed_forced_hits") or {}
        result.audit_rules = audit_rule_counts(cfg)
    from .reporting.html import render
    out = Path(args.output) if args.output else cfg.report_dir / "report.html"
    # Day-over-day (#225): the previous report.json, before it is replaced.
    try:
        from .engine import ssh_surge_findings
        from .model import ServiceReport
        from .reporting.data import previous_attack

        prev = previous_attack(out.with_suffix(".json"))
        if prev and isinstance(result.attackers, dict):
            result.attackers["previous"] = prev
            surge = ssh_surge_findings(result.attackers)
            if surge:
                result.services.append(ServiceReport(service="sshd", present=True,
                                                     findings=surge))
    except Exception:
        pass  # a comparison must never break a report
    out.parent.mkdir(parents=True, exist_ok=True)
    lang = getattr(args, "lang", None) or cfg.report.lang
    out.write_text(render(result, lang=lang), encoding="utf-8")
    # The same run as data, for consoles and collectors (#211). A failure here
    # must not lose the HTML report that was just written.
    try:
        from .reporting.data import write_report_data
        write_report_data(out.with_suffix(".json"), result)
    except Exception as exc:  # noqa: BLE001
        print(f"kevward: could not write {out.with_suffix('.json')}: {exc}", file=sys.stderr)
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
    if getattr(args, "warm_cache", False):
        return _warm_cache(cfg, host_terms)
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
            lead = ("n/a on this host"
                    if m["applicability"] in ("not_applicable", "na_release") else "why")
            print(f"      {lead}: {m['applicability_reason']}")
    rest = len(data["matches"]) - limit
    if rest > 0:
        print(f"  ... and {rest} more (all matches: `kevward trends --json` "
              f"or the HTML report)")
    return 0


def cmd_schedule_reboot(args) -> int:
    from . import scheduler
    if args.status:
        # Read-only: never needs root or policy.
        st = scheduler.scheduled_reboot()
        if args.json:
            import json
            print(json.dumps(st))
        else:
            print(f"reboot scheduled: {scheduler.describe(st)}")
        return 0
    cfg = _mkconfig(args, side_effects=True)
    if args.cancel:
        # Cancelling is never harmful, so policy.allow_reboot is not required;
        # an unreadable config still refuses (side_effects=True above).
        ok, msg = scheduler.cancel_reboot()
        print(msg)
        return 0 if ok else 1
    if not cfg.policy.allow_reboot:
        print("refused: policy.allow_reboot is false. Set it to true to permit reboots.")
        return 2
    ok, msg = scheduler.schedule_reboot(args.window or cfg.policy.reboot_window_start)
    print(msg)
    return 0 if ok else 1


def cmd_schedule(args) -> int:
    from . import schedule as sch
    if args.action == "status":
        props, warns = sch.status()
        if args.json:
            import json
            print(json.dumps({"timer": props, "warnings": warns}, indent=2))
            return 0
        if props:
            print(f"timer:        {sch.TIMER} ({props.get('UnitFileState') or '?'}, "
                  f"{props.get('ActiveState') or '?'})")
            print(f"schedule:     {sch.calendar_of(props.get('TimersCalendar', ''))}")
            print(f"random delay: {props.get('RandomizedDelayUSec') or '0'}"
                  f" (fixed per host: {props.get('FixedRandomDelay') or '?'})")
            print(f"next run:     {props.get('NextElapseUSecRealtime') or '-'}")
            print(f"last run:     {props.get('LastTriggerUSec') or '-'}"
                  f" (result: {props.get('ServiceResult') or '?'})")
            print(f"drop-in:      {props.get('dropin') or 'none'}")
        for w in warns:
            print(f"warning: {w}")
        return 0
    _mkconfig(args, side_effects=args.yes)
    if args.action == "install":
        ok, msgs = sch.install(args.at, args.jitter, dry_run=not args.yes)
    else:
        if not args.yes:
            print("DRY RUN (pass --yes to uninstall): would disable the timer if kevward "
                  "created it, and remove the 50-kevward.conf drop-in and any unit files "
                  f"listed in {sch.STATE_FILE}")
            return 0
        ok, msgs = sch.uninstall()
    for m in msgs:
        print(m)
    return 0 if ok else 1


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
                      allow_forced=cfg.audit.allowed_forced_commands,
                      allowed_outbound=cfg.audit.allowed_outbound)


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
    a.add_argument("--expect-plan", metavar="SHA256",
                   help="install only if the plan still has this plan_hash (ssh-gate)")
    a.add_argument("--job", metavar="ID", help=argparse.SUPPRESS)
    a.add_argument("--reboot-at", metavar="ISO8601", help=argparse.SUPPRESS)
    a.set_defaults(func=cmd_apply)

    r = sub.add_parser("report", help="write HTML posture report")
    _add_common(r)
    r.add_argument("-o", "--output", help="output HTML path")
    r.add_argument("--trends", action="store_true", help="include CISA KEV trends (network)")
    r.add_argument("--audit", action="store_true",
                   help="include host compromise indicators (read-only; sudo for full view)")
    r.add_argument("--lang", choices=["en", "ja"],
                   help="report language (default: [report] lang in config, else en)")
    r.set_defaults(func=cmd_report)

    t = sub.add_parser("trends", help="actively-exploited CVEs relevant to host")
    _add_common(t)
    t.add_argument("--warm-cache", action="store_true",
                   help="one long pass (up to 10 min) that fills the Ubuntu CVE "
                        "cache so daily reports start warm; prints a summary only")
    t.set_defaults(func=cmd_trends)

    sr = sub.add_parser("schedule-reboot", help="schedule a maintenance-window reboot")
    _add_common(sr)
    sr.add_argument("--window", help="HH:MM local time")
    srg = sr.add_mutually_exclusive_group()
    srg.add_argument("--status", action="store_true",
                     help="show whether a reboot is scheduled (read-only)")
    srg.add_argument("--cancel", action="store_true",
                     help="cancel a scheduled reboot (shutdown -c; needs root)")
    sr.set_defaults(func=cmd_schedule_reboot)

    sc = sub.add_parser("schedule", help="install / inspect / remove the daily report timer")
    _add_common(sc)
    sc.add_argument("action", choices=["install", "status", "uninstall"])
    sc.add_argument("--at", default=None,
                    help="daily time, HH:MM local (install; default: the time the "
                         "previous install used, else 07:00)")
    sc.add_argument("--jitter", default=None,
                    help="random delay, fixed per host (install; e.g. 20min, 900s; "
                         "default: as before, else 20min)")
    sc.add_argument("--yes", action="store_true",
                    help="actually write/remove units (otherwise a dry run)")
    sc.set_defaults(func=cmd_schedule)

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

    sg = sub.add_parser(
        "ssh-gate",
        help="forced command for console keys: one JSON request on stdin (#185)",
    )
    sg.add_argument("--role", required=True, choices=["read", "operate"])
    sg.add_argument("-c", "--config", help="path to config.toml")
    sg.set_defaults(func=cmd_ssh_gate)

    su = sub.add_parser(
        "setup",
        help="make this host console-ready: ssh-gate keys, sudoers, timer (#191)",
    )
    su.add_argument("--console-user", help="user whose authorized_keys get the gate lines")
    su.add_argument("--read-key", help="public key line for the read role")
    su.add_argument("--operate-key", help="public key line for the operate role "
                    "(also writes /etc/sudoers.d/kevward-ssh-gate)")
    su.add_argument("--ssh-gate", action="store_true", help="set [ssh_gate] enabled = true")
    su.add_argument("--self-update", action="store_true",
                    help="set [ssh_gate] self_update = true (console may update kevward)")
    su.add_argument("--allow-reboot", action="store_true",
                    help="set [policy] allow_reboot = true (console may schedule reboots)")
    su.add_argument("--timer", action="store_true", help="install the daily report timer")
    su.add_argument("--fail2ban-ignore", action="append", metavar="IP/CIDR",
                    help="never ban this address (repeatable; only if fail2ban exists)")
    su.add_argument("--refresh", action="store_true",
                    help="post-update steps only (used by ssh-gate self.update)")
    su.add_argument("--restore", action="store_true",
                    help="put back what `kevward uninstall` saved (keys, timer, fail2ban)")
    su.add_argument("--dry-run", action="store_true", help="list the changes, write nothing")
    su.add_argument("--json", action="store_true", help="one line of JSON (ssh-gate envelope)")
    su.set_defaults(func=cmd_setup)

    un = sub.add_parser(
        "uninstall",
        help="remove kevward from this host (dry run unless --yes, #192)",
    )
    un.add_argument("--yes", action="store_true", help="actually remove (default: dry run)")
    un.add_argument("--purge", action="store_true",
                    help="also delete /etc/kevward, /var/log/kevward, /var/lib/kevward, "
                         "/var/cache/kevward")
    un.add_argument("--remove-collector-keys", action="store_true",
                    help='also remove `command="cat /var/log/kevward/report.html"` keys')
    un.add_argument("--json", action="store_true", help="one line of JSON (ssh-gate envelope)")
    un.set_defaults(func=cmd_uninstall)

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
