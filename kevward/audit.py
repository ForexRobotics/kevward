"""Host compromise indicators (`kevward audit`) — read-only, local host only.

This is a *detection* aid, not a scanner and not a cleaner. It looks at the
host kevward runs on for the tell-tale signs of a post-intrusion foothold:

- **Reverse SSH / tunnels** — local ``ssh``/``autossh`` processes doing remote
  (``-R``) or dynamic (``-D``) forwarding, a classic exfil/pivot backdoor.
- **Suspicious outbound / listeners** — an established *outbound* connection to
  an external host owned by a shell/interpreter (a reverse shell), or a shell
  listening on a non-loopback address (a bind backdoor).
- **Persistence** — ``/etc/ld.so.preload``, cron, admin-added systemd units,
  shell rc / ``profile.d``, and ``authorized_keys`` carrying reverse-shell or
  downloader patterns, forced commands, or world-writable permissions.

Everything here is read-only: it never changes the system and never touches any
remote host. Findings flag things for a human to look at — they say *possible*,
not *confirmed*. Blocking belongs to ``firewall`` / ``harden``; this only
reports. Full visibility into other users' processes, sockets and files needs
root (``sudo``).
"""

from __future__ import annotations

import ipaddress
import os
import re

from .model import Finding, FindingKind, Severity
from .util import is_root, run

# Processes that should not normally hold a socket to an external host or
# listen on a public address — doing so is a strong reverse/bind-shell signal.
_SHELLS = {
    "bash", "sh", "dash", "zsh", "ksh", "busybox",
    "nc", "ncat", "netcat", "socat",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
}

# Outbound destination ports where a connection is ordinary (http/s, DNS, NTP,
# mail submission/retrieval, SSH, common DBs). Used only to keep the *info*
# "unexpected outbound" list quiet; it never suppresses a shell-owned socket.
_WELL_KNOWN_OUT = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636,
    853, 993, 995, 2049, 3306, 5432, 6379, 11211, 27017,
}

# Reverse-shell / downloader / obfuscation patterns, shared by the cron, unit,
# rc and in-line checks. Conservative: aimed at high-signal, low-noise hits.
_REVSHELL = re.compile(
    r"(/dev/tcp/\d|/dev/udp/\d|bash\s+-i|sh\s+-i|"
    r"\bnc(?:at)?\b[^|&;]*\s-e\b|\bsocat\b[^|&;]*\bexec|mkfifo\b.*\|)",
    re.I,
)
_DOWNLOAD_PIPE = re.compile(
    r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(ba|da|z)?sh\b", re.I
)
_OBFUSC = re.compile(
    r"\bbase64\b\s+-d|\bpython[0-9]?\b\s+-c\b[^\n]*\bsocket\b|"
    r"\bperl\b\s+-e\b[^\n]*\bsocket\b",
    re.I,
)

# Paths an ExecStart/cmd should not normally run from (also matches after
# "ExecStart=" and "ExecStart=-", i.e. an "=" immediately before the path).
_TEMP_PATH = re.compile(r"(?:^|[\s=])-?(/tmp/|/var/tmp/|/dev/shm/|/run/user/)")


# --------------------------------------------------------------------------- #
# Pure classifiers (unit-tested without root, a network, or the real host)
# --------------------------------------------------------------------------- #
def is_external_ip(ip: str) -> bool:
    """True for a routable, non-local peer (not RFC1918/loopback/link-local)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_multicast or a.is_reserved or a.is_unspecified
    )


def is_suspicious_cmdline(text: str) -> bool:
    """Reverse-shell, download-pipe-to-shell, or obfuscated-exec pattern."""
    return bool(
        _REVSHELL.search(text) or _DOWNLOAD_PIPE.search(text) or _OBFUSC.search(text)
    )


def is_reverse_ssh(argv: list[str]) -> str | None:
    """Reverse/dynamic SSH forwarding *from* this host (backdoor / pivot).

    Returns a short reason for ``-R`` / ``RemoteForward`` (reverse tunnel) or
    ``-D`` / ``DynamicForward`` (SOCKS proxy), else None. Handles clustered
    short flags like ``-fNR``."""
    joined = " ".join(argv)
    short = [a[1:] for a in argv if a.startswith("-") and not a.startswith("--")]
    if any("R" in c for c in short) or re.search(r"\bRemoteForward\b", joined, re.I):
        return "reverse SSH tunnel (-R / RemoteForward)"
    if any("D" in c for c in short) or re.search(r"\bDynamicForward\b", joined, re.I):
        return "SSH dynamic SOCKS proxy (-D / DynamicForward)"
    return None


def is_suspicious_exec(exec_line: str) -> str | None:
    """Why a systemd ExecStart line looks like a foothold, or None."""
    if _TEMP_PATH.search(exec_line):
        return "runs from a world-writable/temp path"
    if is_suspicious_cmdline(exec_line):
        return "reverse-shell / downloader pattern"
    return None


def _split_hostport(addr: str) -> tuple[str | None, int | None]:
    """'1.2.3.4:443' or '[::1]:443' -> (host, port); (None, None) if not sane."""
    if addr.startswith("["):
        host, _, port = addr[1:].partition("]:")
    else:
        host, _, port = addr.rpartition(":")
    if not port.isdigit():
        return None, None
    return host or None, int(port)


def _proc_of(ss_line: str) -> str:
    m = re.search(r'\(\("([^"]+)",pid=\d+', ss_line)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- #
# Collectors (read the host; resilient and read-only)
# --------------------------------------------------------------------------- #
def _f(sev: Severity, title: str, detail: str = "") -> Finding:
    return Finding(service="audit", kind=FindingKind.CONFIG,
                   severity=sev, title=title, detail=detail)


def _iter_procs():
    """Yield (pid, basename, argv) for every readable process."""
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return
    for pid in pids:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
        if argv:
            yield pid, os.path.basename(argv[0]), argv


def check_reverse_ssh() -> list[Finding]:
    out: list[Finding] = []
    for pid, name, argv in _iter_procs():
        if name not in ("ssh", "autossh"):
            continue
        reason = is_reverse_ssh(argv)
        if reason:
            sev = Severity.HIGH if reason.startswith("reverse") else Severity.MEDIUM
            out.append(_f(sev, f"{reason} — review (pid {pid})",
                          detail=" ".join(argv)[:200]))
    return out


def check_connections(max_info: int = 15) -> list[Finding]:
    """Established outbound + listeners via ``ss``. Inbound to our own listening
    ports is skipped (it is not a foothold signal)."""
    out: list[Finding] = []
    r = run(["ss", "-tnap"], timeout=20)
    if not r.ok:
        return out
    rows = []
    listen_ports: set[int] = set()
    for line in r.out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        state, local, peer = parts[0], parts[3], parts[4]
        rows.append((state, local, peer, line))
        if state == "LISTEN":
            _, lport = _split_hostport(local)
            if lport is not None:
                listen_ports.add(lport)
    info_count = 0
    for state, local, peer, line in rows:
        proc = _proc_of(line)
        if state == "LISTEN":
            lhost, _ = _split_hostport(local)
            if proc in _SHELLS and lhost not in (None, "127.0.0.1", "::1"):
                out.append(_f(Severity.HIGH,
                              f"shell listening on {local} (possible bind backdoor): "
                              f"{proc}", detail=line.strip()[:200]))
            continue
        if state != "ESTAB":
            continue
        lhost, lport = _split_hostport(local)
        phost, pport = _split_hostport(peer)
        if phost is None or lport in listen_ports:
            continue  # inbound to a local service — not this check's concern
        if not is_external_ip(phost):
            continue
        if proc in _SHELLS:
            out.append(_f(Severity.HIGH,
                          f"possible reverse shell: {proc or '?'} -> {phost}:{pport}",
                          detail=line.strip()[:200]))
        elif pport not in _WELL_KNOWN_OUT and info_count < max_info:
            info_count += 1
            out.append(_f(Severity.INFO,
                          f"unexpected outbound: {proc or '?'} -> {phost}:{pport}",
                          detail=line.strip()[:200]))
    return out


def _read_head(path: str, n: int = 200) -> str:
    try:
        with open(path, errors="replace") as fh:
            return fh.read(n).strip()
    except OSError:
        return ""


def _home_dirs() -> list[str]:
    homes: list[str] = []
    try:
        homes = [os.path.join("/home", n) for n in os.listdir("/home")]
    except OSError:
        pass
    return homes


def _check_cron() -> list[Finding]:
    out: list[Finding] = []
    files = ["/etc/crontab"]
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly",
              "/var/spool/cron/crontabs", "/var/spool/cron"):
        try:
            files += [os.path.join(d, n) for n in os.listdir(d)]
        except OSError:
            continue
    for f in files:
        try:
            with open(f, errors="replace") as fh:
                for ln in fh:
                    s = ln.strip()
                    if s and not s.startswith("#") and is_suspicious_cmdline(s):
                        out.append(_f(Severity.HIGH,
                                      f"suspicious cron entry in {f}",
                                      detail=s[:200]))
        except OSError:
            continue
    return out


def _check_units() -> list[Finding]:
    out: list[Finding] = []
    base = "/etc/systemd/system"
    try:
        names = [n for n in os.listdir(base) if n.endswith(".service")]
    except OSError:
        return out
    for n in names:
        try:
            with open(os.path.join(base, n), errors="replace") as fh:
                for ln in fh:
                    s = ln.strip()
                    if s.startswith("ExecStart"):
                        reason = is_suspicious_exec(s)
                        if reason:
                            out.append(_f(Severity.HIGH,
                                          f"suspicious systemd unit {n}: {reason}",
                                          detail=s[:200]))
        except OSError:
            continue
    return out


def _check_rc() -> list[Finding]:
    out: list[Finding] = []
    files = ["/etc/bash.bashrc", "/etc/profile"]
    try:
        files += [os.path.join("/etc/profile.d", n)
                  for n in os.listdir("/etc/profile.d")]
    except OSError:
        pass
    for home in ["/root", *_home_dirs()]:
        files += [os.path.join(home, rc)
                  for rc in (".bashrc", ".profile", ".bash_profile", ".bash_login")]
    for f in files:
        try:
            with open(f, errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        for ln in content.splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and is_suspicious_cmdline(s):
                out.append(_f(Severity.MEDIUM, f"suspicious line in {f}",
                              detail=s[:200]))
                break  # one finding per file is enough to prompt a look
    return out


def _check_authkeys() -> list[Finding]:
    """Only emit when something is off (world-writable or a forced command);
    an ordinary authorized_keys is not a finding."""
    out: list[Finding] = []
    paths = ["/root/.ssh/authorized_keys"]
    for home in _home_dirs():
        paths.append(os.path.join(home, ".ssh", "authorized_keys"))
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        forced = 0
        try:
            with open(p, errors="replace") as fh:
                for ln in fh:
                    s = ln.strip()
                    if s and not s.startswith("#") and re.search(r'\bcommand="', s):
                        forced += 1
        except OSError:
            continue
        world_writable = bool(st.st_mode & 0o022)
        if world_writable:
            out.append(_f(Severity.MEDIUM,
                          f"authorized_keys is group/world-writable: {p}",
                          detail=f"mode {oct(st.st_mode & 0o777)}"))
        if forced:
            out.append(_f(Severity.LOW,
                          f"authorized_keys has {forced} forced-command key(s): {p}",
                          detail="forced commands can be legitimate (backup/rsync) "
                                 "but are worth confirming"))
    return out


def check_persistence() -> list[Finding]:
    out: list[Finding] = []
    try:
        if os.path.getsize("/etc/ld.so.preload") > 0:
            out.append(_f(Severity.HIGH,
                          "system-wide LD_PRELOAD set (/etc/ld.so.preload non-empty)",
                          detail=_read_head("/etc/ld.so.preload")))
    except OSError:
        pass
    out += _check_cron()
    out += _check_units()
    out += _check_rc()
    out += _check_authkeys()
    return out


def audit() -> list[Finding]:
    findings = check_reverse_ssh() + check_connections() + check_persistence()
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("  ok — no compromise indicators found")
        return
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        print(f"  - {sev.upper():7} {f.title}")
        if f.detail:
            print(f"            {f.detail}")


def run_cli(use_json: bool) -> int:
    findings = audit()
    if use_json:
        import json
        print(json.dumps([f.to_dict() for f in findings], indent=2,
                         ensure_ascii=False))
    else:
        _print_findings(findings)
        if not is_root():
            print("note: run with sudo for full visibility into other users' "
                  "processes, sockets and files.")
    # Read-only: exit 0 regardless. The findings themselves are the signal.
    return 0
