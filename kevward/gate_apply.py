# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""ssh-gate phase 2 (a): ``plan``, ``apply.start`` and ``job.get`` (#197).

What a console does is what an operator types by hand: ``kevward apply``
(dry run), read it, then ``kevward apply --yes``. Two rules hold it together:

* **What is installed is what was reviewed.** ``plan`` returns a
  ``plan_hash``; ``apply.start`` must send it back, and both the gate and the
  detached job rebuild the plan as root and refuse when the hash differs. The
  job then installs from that same apt simulation (``engine.run(fresh=False)``).
* **apt never depends on the SSH connection.** The job runs in its own
  transient systemd unit and writes its state to ``/var/lib/kevward/jobs/``.

Apply policy (``apply_security``, ``apply_minor``, per-service overrides)
always comes from the host's config.toml: nothing in a request can widen it.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Config
from .ssh_gate import CHANGES_FILE, UPDATE_LOCK, VENV_PREFIX, GateError

JOBS_DIR = Path("/var/lib/kevward/jobs")
KEEP_JOBS = 20
LOG_TAIL = 40
APT_LOCK = Path("/var/lib/dpkg/lock-frontend")
_JOB_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PLAN_KINDS = {"security_update": "security", "minor_upgrade": "minor"}
EXIT_PLAN_CHANGED = 3
EXIT_BUSY = 4


# --- the plan --------------------------------------------------------------------

def plan_policy(cfg: Config) -> dict:
    """The host's effective apply policy, as it goes into the hash."""
    p = cfg.policy
    return {
        "apply_security": p.apply_security,
        "apply_minor": p.apply_minor,
        "services": sorted(p.services),
        "overrides": {k: {kk: v[kk] for kk in sorted(v)} for k, v in sorted(p.overrides.items())
                      if isinstance(v, dict)},
    }


def plan_hash(items: list[dict], policy: dict) -> str:
    """sha256 of a canonical JSON of what will be installed and why. Pure."""
    canon = {
        "items": sorted(({k: it.get(k) for k in ("package", "from", "to", "origin", "kind")}
                         for it in items), key=lambda x: x["package"]),
        "policy": policy,
    }
    raw = json.dumps(canon, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _kind(f) -> str:
    return f.kind if isinstance(f.kind, str) else f.kind.value


def build_plan(result, cfg: Config) -> dict:
    """A dry-run RunResult -> the plan a console reviews. Pure."""
    from .cli import plan_tail

    planned: dict[str, str] = {}
    for s in result.services:
        for a in s.actions:
            if a.description.startswith("install: "):
                for p in a.description.removeprefix("install: ").split(", "):
                    planned.setdefault(p, s.service)
    items: list[dict] = []
    skipped: list[dict] = []
    seen: set[str] = set()
    for s in result.services:
        sp = cfg.policy.for_service(s.service)
        for f in s.findings:
            kind = _PLAN_KINDS.get(_kind(f))
            if not kind:
                continue
            for p in f.refs:
                if p in seen:
                    continue
                seen.add(p)
                entry = {"package": p, "service": planned.get(p, s.service),
                         "from": f.package_versions.get(p) or f.current_version,
                         "to": f.fixed_version, "kind": kind, "origin": f.origin}
                if p in planned:
                    items.append(entry)
                    continue
                if kind == "minor" and not sp.apply_minor:
                    reason = "apply_minor is off"
                elif kind == "security" and not sp.apply_security:
                    reason = "apply_security is off"
                else:
                    reason = "not applied by kevward for this service"
                skipped.append({**entry, "reason": reason})
    for p, svc in planned.items():  # an action without a finding: still listed
        if p not in seen:
            items.append({"package": p, "service": svc, "from": None, "to": None,
                          "kind": "other", "origin": None})
    items.sort(key=lambda x: x["package"])
    skipped.sort(key=lambda x: x["package"])
    policy = plan_policy(cfg)
    _tail, reboot = plan_tail(result, cfg.policy.apply_minor)
    return {"plan_hash": plan_hash(items, policy), "items": items, "skipped": skipped,
            "policy": policy, "reboot_expected": bool(reboot),
            "generated_at": result.generated_at, "apt_refresh": result.apt_refresh}


def compute_plan(cfg: Config, *, engine_run=None, fresh: bool = True) -> tuple[dict, object]:
    """Dry-run apply as this process (root or not). Prints go nowhere: on the
    gate, stdout is the JSON envelope."""
    from . import engine
    from .util import is_root

    engine_run = engine_run or engine.run
    with contextlib.redirect_stdout(io.StringIO()):
        result = engine_run(cfg, do_apply=True, dry_run=True, fresh=fresh)
    plan = build_plan(result, cfg)
    plan["as_root"] = is_root()
    return plan, result


# --- jobs ------------------------------------------------------------------------

def _job_path(jobs_dir: Path, job_id: str) -> Path:
    return jobs_dir / f"{job_id}.json"


def write_job(jobs_dir: Path, job: dict) -> None:
    jobs_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    path = _job_path(jobs_dir, job["job_id"])
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(job, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_job(jobs_dir: Path, job_id: str) -> dict | None:
    try:
        return json.loads(_job_path(jobs_dir, job_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def update_job(jobs_dir: Path, job_id: str, **fields) -> dict:
    job = read_job(jobs_dir, job_id) or {"job_id": job_id, "kind": "apply"}
    job.update(fields)
    write_job(jobs_dir, job)
    return job


def prune_jobs(jobs_dir: Path, keep: int = KEEP_JOBS) -> None:
    """Keep the newest ``keep`` jobs (ids sort by time) and never a running one."""
    try:
        ids = sorted(p.stem for p in jobs_dir.glob("*.json") if _JOB_ID.match(p.stem))
    except OSError:
        return
    for jid in ids[:-keep] if keep else ids:
        job = read_job(jobs_dir, jid) or {}
        if job.get("state") in ("starting", "running"):
            continue
        for suffix in (".json", ".log"):
            with contextlib.suppress(OSError):
                (jobs_dir / f"{jid}{suffix}").unlink()


def new_job_id(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def unit_name(job_id: str) -> str:
    return f"kevward-apply-{job_id}"


def _unit_active(unit: str) -> bool:
    from .util import run

    r = run(["systemctl", "is-active", unit], timeout=10)
    return r.out.strip() in ("active", "activating", "reloading")


def _running_jobs(jobs_dir: Path, unit_active) -> list[str]:
    out = []
    try:
        paths = sorted(jobs_dir.glob("*.json"))
    except OSError:
        return out
    for p in paths:
        job = read_job(jobs_dir, p.stem) or {}
        if job.get("state") in ("starting", "running") and unit_active(unit_name(p.stem)):
            out.append(p.stem)
    return out


def _lock_free(path: Path) -> bool:
    """True if nobody holds ``path`` (flock), without keeping it."""
    import fcntl

    try:
        with open(path, "a") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            fcntl.flock(fh, fcntl.LOCK_UN)
            return True
    except OSError:
        return True


def _apt_free(path: Path = APT_LOCK) -> bool:
    """dpkg/apt take fcntl locks on lock-frontend; probe without waiting."""
    import fcntl

    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return True  # not root / no dpkg: apt-get will say so itself
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    else:
        fcntl.lockf(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def busy_reason(jobs_dir: Path, *, unit_active=None, lock_path: Path = UPDATE_LOCK,
                apt_lock: Path = APT_LOCK) -> str | None:
    running = _running_jobs(jobs_dir, unit_active or _unit_active)
    if running:
        return f"apply job {running[-1]} is still running"
    if not _lock_free(lock_path):
        return "a self.update or apply is running"
    if not _apt_free(apt_lock):
        return "apt/dpkg is running"
    return None


def _record(changes_file: Path, rec: dict) -> None:
    try:
        changes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(changes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def _launcher_exe() -> str:
    exe = VENV_PREFIX / "bin" / "kevward"
    if exe.is_file():
        return str(exe)
    from .schedule import kevward_exe

    return kevward_exe()


# --- gate ops --------------------------------------------------------------------

def op_plan(cfg: Config, *, compute=None) -> dict:
    plan, _ = (compute or compute_plan)(cfg)
    return plan


def _reboot_arg(cfg: Config, value, now: datetime) -> dict:
    from .gate_ops import MAX_LEAD, MIN_LEAD, _parse_at

    if value is None:
        return {"mode": "never"}
    if not isinstance(value, dict):
        raise GateError("bad_request", 'reboot must be {"mode": "never"|"if_required", "at": ...}')
    mode = value.get("mode", "never")
    if mode == "never":
        return {"mode": "never"}
    if mode != "if_required":
        raise GateError("bad_request", 'reboot.mode must be "never" or "if_required"')
    when = _parse_at(value.get("at"))
    if when - now < MIN_LEAD:
        raise GateError("bad_request", "reboot.at must be at least 5 minutes in the future")
    if when - now > MAX_LEAD:
        raise GateError("bad_request", "reboot.at must be within 7 days")
    if not cfg.policy.allow_reboot:
        raise GateError("forbidden", "reboots are not allowed on this host "
                        "([policy] allow_reboot = true in the host's config)")
    return {"mode": "if_required",
            "at": when.astimezone(timezone.utc).isoformat(timespec="seconds")}


def op_apply_start(cfg: Config, args: dict, *, config_path: Path, changes_file: Path,
                   client: str, now: datetime, jobs_dir: Path = JOBS_DIR, compute=None,
                   launcher=None, busy=None) -> dict:
    from .util import run

    expect = args.get("expect_plan")
    if not isinstance(expect, str) or not _HASH.match(expect):
        raise GateError("bad_request", "expect_plan must be the 64-hex plan_hash from plan")
    unknown = set(args) - {"expect_plan", "reboot"}
    if unknown:  # e.g. "minor": policy is host-only
        raise GateError("bad_request", f"unknown argument(s): {', '.join(sorted(unknown))} "
                        "(apply policy comes from the host's config)")
    reboot = _reboot_arg(cfg, args.get("reboot"), now)
    why = (busy or (lambda: busy_reason(jobs_dir)))()
    if why:
        raise GateError("conflict", why)
    plan, _ = (compute or compute_plan)(cfg)
    if not plan.get("as_root"):
        raise GateError("forbidden", "apply.start must run as root (the operate role, via sudo)")
    if plan["plan_hash"] != expect:
        raise GateError("conflict", f"the plan changed; new plan_hash {plan['plan_hash']} "
                        "(take the plan again and review it)")
    job_id = new_job_id(now)
    unit = unit_name(job_id)
    job = {"job_id": job_id, "kind": "apply", "state": "starting", "unit": unit,
           "started": now.isoformat(timespec="seconds"), "finished": None,
           "exit_code": None, "client": client, "plan_hash": expect,
           "packages": [it["package"] for it in plan["items"]], "reboot": reboot,
           "result": None}
    write_job(jobs_dir, job)
    argv = ["systemd-run", f"--unit={unit}", "--collect", "--quiet",
            "--description=kevward apply (ssh-gate job)",
            _launcher_exe(), "apply", "-c", str(config_path), "--yes",
            "--expect-plan", expect, "--job", job_id]
    if reboot["mode"] == "if_required":
        argv += ["--reboot-at", reboot["at"]]
    r = (launcher or run)(argv, timeout=30)
    if r.rc != 0:
        err = (r.err or r.out).strip()[:200]
        update_job(jobs_dir, job_id, state="failed", exit_code=r.rc,
                   finished=now.isoformat(timespec="seconds"),
                   error=f"systemd-run failed: {err}")
        raise GateError("internal", f"systemd-run failed: {err}")
    prune_jobs(jobs_dir)
    _record(changes_file, {"time": now.isoformat(timespec="seconds"), "client": client,
                           "kind": "apply.start", "job_id": job_id, "plan_hash": expect,
                           "packages": job["packages"], "reboot": reboot})
    return {"job_id": job_id, "unit": unit, "plan_hash": expect,
            "packages": job["packages"], "reboot": reboot}


def tail(path: Path, n: int = LOG_TAIL) -> list[str]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 64 * 1024))
            data = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return data.splitlines()[-n:]


def op_job_get(args: dict, *, jobs_dir: Path = JOBS_DIR, unit_active=None) -> dict:
    job_id = args.get("job_id")
    if not isinstance(job_id, str) or not _JOB_ID.match(job_id):
        raise GateError("bad_request", "job_id must look like 20261122T010000Z-a1b2c3")
    job = read_job(jobs_dir, job_id)
    if job is None:
        raise GateError("not_found", f"no job {job_id}")
    if job.get("state") in ("starting", "running") and \
            not (unit_active or _unit_active)(job.get("unit") or unit_name(job_id)):
        # The unit is gone but never wrote a result: killed, OOM, reboot.
        job = {**job, "state": "failed",
               "error": "the job stopped without recording a result (see journalctl -u "
                        f"{job.get('unit') or unit_name(job_id)})"}
    job.pop("client", None)
    job["log_tail"] = tail(jobs_dir / f"{job_id}.log")
    return job


# --- the detached job (`kevward apply --yes --expect-plan H --job ID`) -----------

def _redirect_output(log: Path) -> None:
    """Send fds 1 and 2 (and apt-get's output with them) to the job log."""
    log.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    import sys

    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)


def _schedule_job_reboot(at_iso: str, job_id: str, *, now: datetime, runner) -> dict:
    """After the install: reboot at ``at`` (or in a minute if that has passed)."""
    from . import scheduler

    current = scheduler.scheduled_reboot()
    if current.get("state") == "scheduled":
        return {"scheduled": current, "note": "a reboot was already scheduled; kept"}
    at = datetime.fromisoformat(at_iso)
    minutes = max(1, math.ceil((at - now).total_seconds() / 60))
    r = runner(["shutdown", "-r", f"+{minutes}", f"kevward (ssh-gate job {job_id})"],
               timeout=30)
    if r.rc != 0:
        return {"error": "shutdown failed: " + (r.err or r.out).strip()[:200]}
    when = (now + timedelta(minutes=minutes)).astimezone(timezone.utc)
    return {"scheduled": {"state": "scheduled", "at": when.isoformat(timespec="seconds"),
                          "mode": "reboot"}}


def run_job(cfg: Config, *, expect: str | None, job_id: str | None,
            reboot_at: str | None = None, jobs_dir: Path = JOBS_DIR,
            changes_file: Path = CHANGES_FILE, engine_run=None, runner=None,
            reboot_pending=None, now_fn=None, lock_path: Path = UPDATE_LOCK,
            redirect: bool = True) -> int:
    """Body of a gate apply job. Returns the exit code."""
    import fcntl

    from . import engine
    from .util import reboot_pending as _rp
    from .util import run

    engine_run = engine_run or engine.run
    runner = runner or run
    now_fn = now_fn or (lambda: datetime.now(timezone.utc))
    if job_id is not None and not _JOB_ID.match(job_id):
        print(f"kevward: bad --job id {job_id!r}")
        return 2
    if expect is not None and not _HASH.match(expect):
        print("kevward: --expect-plan needs a 64-hex plan_hash")
        return 2
    job = read_job(jobs_dir, job_id) if job_id else None
    client = (job or {}).get("client", "")
    if job_id and redirect:
        _redirect_output(jobs_dir / f"{job_id}.log")

    def finish(state: str, code: int, result: dict | None = None, error: str = "") -> int:
        t = now_fn().isoformat(timespec="seconds")
        if job_id:
            update_job(jobs_dir, job_id, state=state, exit_code=code, finished=t,
                       result=result, **({"error": error} if error else {}))
            _record(changes_file, {"time": t, "client": client, "kind": "apply.finish",
                                   "job_id": job_id, "state": state, "exit_code": code,
                                   "result": result, "error": error or None})
        if error:
            print(f"kevward: {error}")
        return code

    if job_id:
        update_job(jobs_dir, job_id, state="running", pid=os.getpid())
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return finish("failed", EXIT_BUSY, error="a self.update or apply is running")
        plan, _ = compute_plan(cfg, engine_run=engine_run)
        print(f"plan {plan['plan_hash']}: {len(plan['items'])} package(s)", flush=True)
        if expect and plan["plan_hash"] != expect:
            return finish("failed", EXIT_PLAN_CHANGED, result={"plan_hash": plan["plan_hash"]},
                          error=f"the plan changed (expected {expect[:12]}…, "
                                f"now {plan['plan_hash'][:12]}…); nothing was installed")
        result = engine_run(cfg, do_apply=True, dry_run=False, fresh=False)
        installed: list[str] = []
        failed: list[dict] = []
        for svc in result.services:
            for a in svc.actions:
                pkgs = a.description.removeprefix("install: ").split(", ")
                if a.ok and not a.dry_run:
                    installed += pkgs
                    print(f"[{svc.service}] ok: {a.description}", flush=True)
                else:
                    reason = (a.output or "").strip().splitlines()[:1]
                    failed.append({"service": svc.service, "packages": pkgs,
                                   "error": reason[0][:200] if reason else ""})
                    print(f"[{svc.service}] FAIL: {a.description}", flush=True)
    needs = bool((reboot_pending or _rp)()) or result.reboot_required
    res: dict = {"installed": sorted(set(installed)), "failed": failed,
                 "reboot_required": needs, "reboot": None}
    if reboot_at and needs:
        if cfg.policy.allow_reboot:
            res["reboot"] = _schedule_job_reboot(reboot_at, job_id or "-", now=now_fn(),
                                                 runner=runner)
        else:
            res["reboot"] = {"error": "[policy] allow_reboot is off on this host"}
        print(f"reboot: {json.dumps(res['reboot'], ensure_ascii=False)}", flush=True)
    if failed:
        return finish("failed", 1, res, error=f"{len(failed)} install action(s) failed")
    return finish("succeeded", 0, res)
