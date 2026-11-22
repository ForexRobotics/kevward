# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""`kevward ssh-gate`: the forced command for console / collection keys (#185).

Used as the ``command="..."`` of an authorized_keys line, it replaces the
shell for that key. One connection carries one JSON request on stdin; one
line of JSON comes back on stdout, in the same envelope as stille-pro
``dispatch``::

    {"ok": true, "data": {...}}
    {"ok": false, "error": "<message>", "code": "<code>"}

It restricts what comes *in*; it never connects anywhere. Off unless the
host's own config has ``[ssh_gate] enabled = true`` (not writable through the
gate). Roles come only from the forced command line:

- ``read``    (no sudo): version, report.get, config.get, config.schema
- ``operate`` (``sudo -n`` with an exact-match sudoers line): + config.set

``config.set`` only touches keys on an allowlist that cannot weaken detection
or protection and are not paths; it checks the caller's view of the file
(sha256), validates the candidate with kevward's own loader, keeps a backup,
replaces the file atomically, logs to syslog and to a change log that the
report shows for 7 days.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import math
import os
import platform
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import DEFAULT_PATHS, TOP_LEVEL_KEYS, Config, _fields, _tables, tomllib

PROTOCOL = 1
MAX_REQUEST = 256 * 1024
READ_TIMEOUT_S = 10
KEEP_BACKUPS = 10
CHANGES_FILE = Path("/var/lib/kevward/ssh-gate-changes.jsonl")
CHANGE_NOTICE_DAYS = 7

ROLES = ("read", "operate")
READ_OPS = ("version", "report.get", "config.get", "config.schema",
            "reboot.status", "schedule.status", "plan", "job.get")
OPERATE_OPS = READ_OPS + ("config.set", "self.update", "reboot.schedule", "reboot.cancel",
                          "schedule.install", "apply.start")

# self.update (#190)
SELF_UPDATE_SINCE = "0.17.0"     # default rollback floor: first release with the op
VENV_PREFIX = Path("/opt/kevward")
UPDATE_TIMEOUT_S = 300
UPDATE_LOCK = Path("/var/lib/kevward/self-update.lock")
INDEX_URL = "https://pypi.org/simple"
_VERSION = re.compile(r"(\d{1,4})\.(\d{1,4})\.(\d{1,4})")

# Keys ssh-gate may write (phase 1): none of them can weaken detection or
# protection, and none is a path.
WRITABLE = {
    "report.lang",
    "trends.version_budget_s",
    "trends.max_version_checks",
    "trends.fetch_workers",
    "apt.install_timeout_s",
}

# Why the rest is read-only, for config.schema (and the console's form).
_WEAKENING = {
    "audit.allowed_outbound", "audit.allowed_forced_commands", "firewall.allow",
    "firewall.block", "firewall.persist", "update.check", "apt.php_release_check",
    "apt.security_origins", "policy.apply_security", "policy.apply_minor",
    "policy.allow_reboot", "policy.reboot_window_start", "policy.services",
    "policy.overrides",
}
_PATHS = {"report_dir"}


class GateError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def ok(data: dict) -> dict:
    return {"ok": True, "data": data}


def fail(code: str, message: str) -> dict:
    return {"ok": False, "error": message, "code": code}


def dumps(resp: dict) -> str:
    """One line of JSON, UTF-8 not escaped (the stille-pro envelope)."""
    return json.dumps(resp, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"


# --- config.schema ------------------------------------------------------------

def _readonly_reason(key: str) -> str:
    if key in WRITABLE:
        return ""
    if key in _PATHS:
        return "path: never writable through ssh-gate"
    if key.startswith("ssh_gate."):
        return "ssh-gate's own settings: change them on the host"
    if key in _WEAKENING:
        return "can weaken detection or protection: change it on the host"
    return "not writable through ssh-gate (phase 1)"


def _field_help(cls: type) -> dict[str, str]:
    """Comment lines directly above each dataclass field. Best effort."""
    try:
        src = inspect.getsource(cls)
    except (OSError, TypeError):
        return {}
    out: dict[str, str] = {}
    comment: list[str] = []
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("#"):
            comment.append(s.lstrip("#").strip())
            continue
        m = re.match(r"(\w+)\s*:", s)
        if m and comment:
            out[m.group(1)] = " ".join(comment)
        comment = []
    return out


def _type_name(value) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list[str]"
    if isinstance(value, dict):
        return "table"
    if isinstance(value, Path):
        return "path"
    return "str" if value is None else type(value).__name__


def schema() -> dict:
    keys = []
    for tname, cls in _tables().items():
        inst = cls()
        helps = _field_help(cls)
        for f in _fields(cls):
            default = getattr(inst, f)
            key = f"{tname}.{f}"
            keys.append({
                "key": key, "table": tname, "name": f, "type": _type_name(default),
                "default": default, "help": helps.get(f, ""),
                "writable": key in WRITABLE, "readonly_reason": _readonly_reason(key),
            })
    for k in TOP_LEVEL_KEYS:
        default = getattr(Config(), k)
        keys.append({"key": k, "table": "", "name": k, "type": _type_name(default),
                     "default": str(default), "help": "", "writable": False,
                     "readonly_reason": _readonly_reason(k)})
    return {"protocol": PROTOCOL, "keys": keys}


# --- TOML writer (the stdlib has none; kevward takes no dependency) -----------

_BARE = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(k: str) -> str:
    return k if _BARE.match(k) else json.dumps(k, ensure_ascii=False)


def _value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise GateError("bad_request", "nan/inf is not allowed")
        return repr(v)
    if isinstance(v, str):
        # JSON string escapes are valid TOML basic-string escapes.
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(_value(x) for x in v) + "]"
    raise GateError("bad_request", f"unsupported value type: {type(v).__name__}")


def to_toml(data: dict) -> str:
    """Serialize the subset of TOML kevward's config uses. Pure."""
    lines: list[str] = ["# Written by `kevward ssh-gate` (#185); comments are not kept,",
                        "# the previous file is in config.toml.bak-<time>.", ""]
    tables: list[tuple[str, dict]] = []
    for k, v in data.items():
        if isinstance(v, dict):
            tables.append((_key(k), v))
        else:
            lines.append(f"{_key(k)} = {_value(v)}")

    def emit(name: str, tbl: dict) -> None:
        sub: list[tuple[str, dict]] = []
        lines.append(f"\n[{name}]")
        for k, v in tbl.items():
            if isinstance(v, dict):
                sub.append((f"{name}.{_key(k)}", v))
            else:
                lines.append(f"{_key(k)} = {_value(v)}")
        for n, t in sub:
            emit(n, t)

    for name, tbl in tables:
        emit(name, tbl)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


# --- ops -----------------------------------------------------------------------

def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def config_path(explicit: str | Path | None = None) -> Path:
    if explicit:
        return Path(explicit)
    for p in DEFAULT_PATHS:
        if p.is_file():
            return p
    return DEFAULT_PATHS[0]


def _effective(cfg: Config) -> dict:
    out = {}
    for tname in _tables():
        out[tname] = dataclasses.asdict(getattr(cfg, tname))
    out["report_dir"] = str(cfg.report_dir)
    return out


def install_info(prefix: Path | None = None) -> dict:
    """How this kevward is installed: the /opt/kevward venv or something else."""
    prefix = prefix or VENV_PREFIX
    here = Path(sys.prefix).resolve()
    is_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if is_venv and here == prefix.resolve() and (prefix / "bin" / "python").exists():
        return {"method": "venv", "prefix": str(prefix)}
    return {"method": "other", "prefix": str(here)}


def op_version(role: str, cfg: Config | None = None) -> dict:
    gate = cfg.ssh_gate if cfg else None
    return {"kevward": __version__, "python": platform.python_version(),
            "protocol": PROTOCOL, "role": role,
            "ops": list(OPERATE_OPS if role == "operate" else READ_OPS),
            "install": install_info(),
            "self_update": bool(gate and gate.self_update),
            "min_version": (gate.min_version if gate and gate.min_version
                            else SELF_UPDATE_SINCE)}


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _pip_tail(text: str, n: int = 40) -> str:
    return "\n".join((text or "").strip().splitlines()[-n:])


def op_self_update(cfg: Config, args: dict, *, changes_file: Path, client: str,
                   now: datetime, runner=None, prefix: Path | None = None,
                   lock_path: Path | None = None) -> dict:
    """pip install kevward==<version> into the /opt/kevward venv (#190)."""
    from .util import run as _run

    runner = runner or _run
    prefix = prefix or VENV_PREFIX
    want = args.get("version")
    if not isinstance(want, str) or not _VERSION.fullmatch(want):
        raise GateError("bad_request", "args.version must be a release version like 0.17.0")
    if not cfg.ssh_gate.self_update:
        raise GateError("forbidden", "self.update is not enabled on this host "
                        "([ssh_gate] self_update = true in the host's config)")
    floor = cfg.ssh_gate.min_version or SELF_UPDATE_SINCE
    if _vtuple(want) < _vtuple(floor):
        raise GateError("forbidden", f"{want} is below this host's minimum {floor} "
                        "([ssh_gate] min_version)")
    inst = install_info(prefix)
    if inst["method"] != "venv":
        raise GateError("forbidden", f"not a venv install in {prefix} "
                        f"(running from {inst['prefix']}); update it by hand")
    old = __version__
    if want == old:
        return {"old": old, "new": old, "downgrade": False, "unchanged": True,
                "duration_s": 0.0, "pip_tail": ""}
    import fcntl

    lock_path = lock_path or UPDATE_LOCK
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise GateError("conflict", "another self.update is running") from None
        t0 = time.monotonic()
        py = str(prefix / "bin" / "python")
        # --isolated: ignore PIP_* variables and user/site pip config; the
        # environment is also replaced. Only the validated version is used.
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
               "HOME": "/root", "PIP_CONFIG_FILE": "/dev/null"}
        r = runner([py, "-m", "pip", "install", "--isolated", "--no-input",
                    "--disable-pip-version-check", "--index-url", INDEX_URL,
                    f"kevward=={want}"], timeout=UPDATE_TIMEOUT_S, env=env,
                   clean_env=True)
        out = (r.out or "") + ("\n" + r.err if r.err else "")
        if r.rc == 124:
            raise GateError("internal", f"pip timed out after {UPDATE_TIMEOUT_S}s")
        if r.rc != 0:
            if ("No matching distribution found" in out
                    or "Could not find a version that satisfies" in out):
                raise GateError("not_found", f"kevward {want} is not on PyPI")
            raise GateError("internal", "pip failed: " + _pip_tail(out, 15))
        chk = runner([str(prefix / "bin" / "kevward"), "--version"], timeout=30,
                     env=env, clean_env=True)
        got = (chk.out or "").strip().split()[-1:] or [""]
        if chk.rc != 0 or got[0] != want:
            raise GateError("internal", f"installed, but `kevward --version` says "
                            f"{(chk.out or chk.err).strip()[:80]!r}, not {want}")
        duration = round(time.monotonic() - t0, 1)
    downgrade = _vtuple(want) < _vtuple(old)
    record = {"time": now.isoformat(timespec="seconds"), "client": client,
              "kind": "self.update", "old": old, "new": want, "downgrade": downgrade}
    try:
        changes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(changes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # syslog still has it
    return {"old": old, "new": want, "downgrade": downgrade, "duration_s": duration,
            "pip_tail": _pip_tail(out)}


def op_report_get(cfg: Config, args: dict) -> dict:
    fmt = args.get("format", "html")
    if fmt not in ("html", "json"):
        raise GateError("bad_request", "format must be 'html' or 'json'")
    p = cfg.report_dir / ("report.html" if fmt == "html" else "last-run.json")
    try:
        raw = p.read_bytes()
        mtime = p.stat().st_mtime
    except FileNotFoundError:
        raise GateError("not_found", f"no report yet: {p}") from None
    except OSError as e:
        raise GateError("internal", f"cannot read {p}: {e.strerror}") from None
    text = raw.decode("utf-8", errors="replace")
    content: object = text
    if fmt == "json":
        try:
            content = json.loads(text)
        except ValueError:
            raise GateError("internal", f"{p} is not valid JSON") from None
    return {"format": fmt, "path": str(p), "sha256": _sha(raw),
            "mtime": datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds"),
            "content": content}


def op_config_get(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = b""
    except OSError as e:
        raise GateError("internal", f"cannot read {path}: {e.strerror}") from None
    cfg = Config.load(path) if raw else Config()
    return {"path": str(path), "exists": bool(raw), "sha256": _sha(raw),
            "text": raw.decode("utf-8", errors="replace"),
            "effective": _effective(cfg), "load_error": cfg.load_error,
            "warnings": cfg.warnings}


def _check_value(key: str, value):
    tname, name = key.split(".", 1)
    default = getattr(_tables()[tname](), name)
    if isinstance(default, bool):
        good = isinstance(value, bool)
    elif isinstance(default, int):
        good = isinstance(value, int) and not isinstance(value, bool)
    elif isinstance(default, float):
        good = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif isinstance(default, str):
        good = isinstance(value, str) and len(value) <= 256
    else:
        good = False
    if not good:
        raise GateError("bad_request", f"{key}: expected {_type_name(default)}")
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise GateError("bad_request", f"{key}: nan/inf is not allowed")
    return float(value) if isinstance(default, float) else value


def _atomic_write(path: Path, text: str) -> None:
    st = path.stat() if path.exists() else None
    fd, tmp = tempfile.mkstemp(prefix=".config.toml.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, (st.st_mode & 0o7777) if st else 0o644)
        if st is not None:
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _prune_backups(path: Path, keep: int = KEEP_BACKUPS) -> None:
    baks = sorted(path.parent.glob(path.name + ".bak-*"))
    for old in baks[:-keep]:
        try:
            old.unlink()
        except OSError:
            pass


def validate_candidate(path: Path, text: str) -> Config:
    """Load ``text`` with kevward's own loader from a temp file next to
    ``path``; GateError(bad_request) on a load error or #186 warnings."""
    fd, cand = tempfile.mkstemp(prefix=".config.candidate.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        cfg = Config.load(cand)
    finally:
        try:
            os.unlink(cand)
        except OSError:
            pass
    if cfg.load_error or cfg.warnings:
        raise GateError("bad_request", "candidate config rejected: "
                        + (cfg.load_error or "; ".join(cfg.warnings)))
    return cfg


def replace_config(path: Path, raw: bytes, text: str, now: datetime) -> Path | None:
    """Back up the old bytes (keep the last 10) and atomically write ``text``."""
    backup = None
    if raw:
        backup = path.with_name(f"{path.name}.bak-{now.strftime('%Y%m%dT%H%M%SZ')}")
        backup.write_bytes(raw)
        try:
            os.chmod(backup, path.stat().st_mode & 0o7777)
        except OSError:
            pass
        _prune_backups(path)
    _atomic_write(path, text)
    return backup


def op_config_set(path: Path, args: dict, *, changes_file: Path, client: str,
                  now: datetime) -> dict:
    sets = args.get("set")
    expect = args.get("expect_sha256")
    if not isinstance(sets, dict) or not sets:
        raise GateError("bad_request", "args.set must be a non-empty object")
    if not isinstance(expect, str) or not re.fullmatch(r"[0-9a-f]{64}", expect):
        raise GateError("bad_request", "args.expect_sha256 must be the sha256 from config.get")
    for key in sets:
        if not isinstance(key, str) or key not in WRITABLE:
            reason = _readonly_reason(key) if isinstance(key, str) else "bad key"
            raise GateError("forbidden", f"{key}: {reason}")
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = b""
    if _sha(raw) != expect:
        raise GateError("conflict", "the config changed since config.get; read it again")
    try:
        data = tomllib.loads(raw.decode("utf-8")) if raw else {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise GateError("bad_request", "the current config is not valid TOML; "
                        "fix it on the host first") from None
    current = Config.from_dict(data)
    if current.warnings:
        raise GateError("bad_request", "the current config has ignored settings; fix "
                        "them on the host first: " + "; ".join(current.warnings))
    changed: dict[str, dict] = {}
    for key, value in sets.items():
        value = _check_value(key, value)
        tname, name = key.split(".", 1)
        tbl = data.setdefault(tname, {})
        old = tbl.get(name, getattr(getattr(current, tname), name))
        tbl[name] = value
        changed[key] = {"old": old, "new": value}
    text = to_toml(data)
    # Validate the candidate with kevward's own loader before it is live.
    cfg = validate_candidate(path, text)
    for key, ch in changed.items():
        tname, name = key.split(".", 1)
        eff = getattr(getattr(cfg, tname), name)
        if eff != ch["new"]:
            raise GateError("bad_request", f"{key}: {ch['new']!r} would be stored as "
                            f"{eff!r} (out of range)")
    backup = replace_config(path, raw, text, now)
    record = {"time": now.isoformat(timespec="seconds"), "client": client,
              "path": str(path), "changes": changed,
              "backup": str(backup) if backup else None}
    try:
        changes_file.parent.mkdir(parents=True, exist_ok=True)
        with open(changes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass  # syslog still has it
    return {"path": str(path), "sha256": _sha(text.encode()), "changes": changed,
            "backup": str(backup) if backup else None}


# --- dispatch --------------------------------------------------------------------

def handle(raw: bytes, role: str, *, path: Path, changes_file: Path = CHANGES_FILE,
           client: str = "", now: datetime | None = None,
           update_opts: dict | None = None, op_opts: dict | None = None) -> dict:
    """One request -> one response. Never raises.

    ``op_opts`` (tests only) is passed to the phase 2 ops: ``runner`` for
    reboot.schedule/cancel, ``paths`` for schedule.install, and ``compute`` /
    ``launcher`` / ``busy`` / ``jobs_dir`` / ``unit_active`` for plan, apply.start
    and job.get.
    """
    now = now or datetime.now(timezone.utc)
    try:
        if role not in ROLES:
            raise GateError("forbidden", f"unknown role: {role!r}")
        if len(raw) > MAX_REQUEST:
            raise GateError("too_large", f"request larger than {MAX_REQUEST} bytes")
        cfg = Config.load(path) if path.is_file() else Config()
        if cfg.load_error or not cfg.ssh_gate.enabled:
            raise GateError("forbidden", "ssh-gate is disabled on this host "
                            "([ssh_gate] enabled = true in the host's config)")
        try:
            req = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise GateError("bad_request", "request is not valid JSON") from None
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            raise GateError("bad_request", 'request must be {"op": "...", "args": {...}}')
        op, args = req["op"], req.get("args", {})
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise GateError("bad_request", "args must be an object")
        allowed = OPERATE_OPS if role == "operate" else READ_OPS
        if op not in OPERATE_OPS:
            raise GateError("unknown_op", f"unknown op: {op!r}")
        if op not in allowed:
            raise GateError("forbidden", f"{op} needs the operate role")
        if op == "version":
            return ok(op_version(role, cfg))
        if op == "report.get":
            return ok(op_report_get(cfg, args))
        if op == "config.get":
            return ok(op_config_get(path))
        if op == "config.schema":
            return ok(schema())
        if op == "self.update":
            return ok(op_self_update(cfg, args, changes_file=changes_file, client=client,
                                     now=now, **(update_opts or {})))
        if op in ("plan", "apply.start", "job.get"):
            return ok(_apply_ops(op, cfg, args, path=path, changes_file=changes_file,
                                 client=client, now=now, opts=op_opts or {}))
        if op.startswith(("reboot.", "schedule.")):
            return ok(_phase2(op, cfg, args, changes_file=changes_file, client=client,
                              now=now, opts=op_opts or {}))
        return ok(op_config_set(path, args, changes_file=changes_file, client=client,
                                now=now))
    except GateError as e:
        return fail(e.code, e.message)
    except Exception as e:  # never a traceback on the wire
        return fail("internal", f"{type(e).__name__}")


def _apply_ops(op: str, cfg: Config, args: dict, *, path: Path, changes_file: Path,
               client: str, now: datetime, opts: dict) -> dict:
    from . import gate_apply as ga

    jobs = {"jobs_dir": opts["jobs_dir"]} if "jobs_dir" in opts else {}
    if op == "plan":
        return ga.op_plan(cfg, compute=opts.get("compute"))
    if op == "job.get":
        return ga.op_job_get(args, unit_active=opts.get("unit_active"), **jobs)
    return ga.op_apply_start(cfg, args, config_path=path, changes_file=changes_file,
                             client=client, now=now, compute=opts.get("compute"),
                             launcher=opts.get("launcher"), busy=opts.get("busy"), **jobs)


def _phase2(op: str, cfg: Config, args: dict, *, changes_file: Path, client: str,
            now: datetime, opts: dict) -> dict:
    from . import gate_ops as g

    kw = {"changes_file": changes_file}
    if op == "reboot.status":
        return g.op_reboot_status(**kw)
    if op == "schedule.status":
        return g.op_schedule_status()
    kw.update(client=client, now=now)
    if op == "reboot.schedule":
        return g.op_reboot_schedule(cfg, args, runner=opts.get("runner"), **kw)
    if op == "reboot.cancel":
        return g.op_reboot_cancel(runner=opts.get("runner"), **kw)
    return g.op_schedule_install(paths=opts.get("paths"), **kw)


def _log(role: str, raw: bytes, resp: dict, client: str) -> None:
    try:
        import syslog

        try:
            op = json.loads(raw.decode("utf-8")).get("op", "?")
        except Exception:
            op = "?"
        status = "ok" if resp.get("ok") else f"refused:{resp.get('code')}"
        extra = ""
        data = resp.get("data") if resp.get("ok") else None
        if isinstance(data, dict) and "changes" in data:
            extra = " changes=" + json.dumps(data["changes"], ensure_ascii=False,
                                             default=str)
        elif isinstance(data, dict) and "new" in data and "old" in data:
            extra = f" update={data['old']}->{data['new']}"
        elif isinstance(data, dict) and isinstance(data.get("scheduled"), dict) \
                and "replaced" in data:
            extra = f" reboot_at={data['scheduled'].get('at')}"
        elif isinstance(data, dict) and "job_id" in data and "unit" in data:
            extra = f" job={data['job_id']} plan={str(data.get('plan_hash'))[:12]}"
        elif isinstance(data, dict) and isinstance(data.get("cancelled"), dict):
            extra = f" reboot_cancelled={data['cancelled'].get('at')}"
        orig = os.environ.get("SSH_ORIGINAL_COMMAND", "")
        syslog.openlog("kevward-ssh-gate", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE if resp.get("ok") else syslog.LOG_WARNING,
                      f"role={role} op={op} {status} client={client or '-'}"
                      + (f" original_command={orig[:120]!r}" if orig else "") + extra)
    except Exception:
        pass


def _read_stdin(limit: int = MAX_REQUEST + 1, timeout: int = READ_TIMEOUT_S) -> bytes:
    import signal

    def _alarm(*_a):
        raise TimeoutError

    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(timeout)
    try:
        return sys.stdin.buffer.read(limit)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def main(role: str, config: str | None = None) -> int:
    client = (os.environ.get("SSH_CONNECTION", "").split() or [""])[0]
    try:
        raw = _read_stdin()
    except TimeoutError:
        resp = fail("bad_request", f"no request within {READ_TIMEOUT_S}s")
        raw = b""
    else:
        resp = handle(raw, role, path=config_path(config), client=client)
    _log(role, raw, resp, client)
    sys.stdout.write(dumps(resp))
    sys.stdout.flush()
    return 0 if resp.get("ok") else 2


# --- report notice --------------------------------------------------------------

def recent_changes(changes_file: Path = CHANGES_FILE, days: int = CHANGE_NOTICE_DAYS,
                   now: float | None = None) -> list[dict]:
    """Change-log records from the last ``days`` days (for the report)."""
    now = now if now is not None else time.time()
    out = []
    try:
        lines = changes_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for ln in lines:
        try:
            rec = json.loads(ln)
            t = datetime.fromisoformat(rec["time"]).timestamp()
        except (ValueError, KeyError, TypeError):
            continue
        if now - t <= days * 86400:
            out.append(rec)
    return out
