# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""What the web server actually serves, and with which PHP-FPM (#85).

On 2026-11-09 answering "which PHP serves the app?" took several manual steps
and one gave a wrong answer (``grep -r`` does not follow the
``sites-enabled/default`` symlink); ``apt autoremove`` would also have removed
the FPM serving production. On 2026-11-13 hokaku ran three FPM versions and
hokaku3 four, including an end-of-life 8.1.

Everything here is read-only. The parsers are pure functions over command
output so they can be unit-tested; the collectors call ``kevward.util.run``
with argv lists and degrade to "unknown" (None) when a command is missing or
needs root.
"""

from __future__ import annotations

import glob
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ..util import have, run

_FPM_SOCK = re.compile(r"php(\d+\.\d+)-fpm(?:\.sock)?")
_FPM_UNIT = re.compile(r"^\s*(?:●\s*)?php(\d+\.\d+)-fpm\.service\s")


@dataclass
class ServerBlock:
    """One nginx ``server { ... }`` block (directives from any nested location)."""

    names: list[str] = field(default_factory=list)
    listen: list[str] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)
    fastcgi: list[str] = field(default_factory=list)
    proxy: list[str] = field(default_factory=list)

    def php_versions(self, upstreams: dict[str, list[str]] | None = None) -> list[str]:
        """PHP versions this block's ``fastcgi_pass`` targets point at."""
        out: list[str] = []
        for target in self.fastcgi:
            targets = (upstreams or {}).get(target, [target])
            for t in targets:
                m = _FPM_SOCK.search(t)
                if m and m.group(1) not in out:
                    out.append(m.group(1))
        return out


def _strip_comment(line: str) -> str:
    # nginx comments start with '#'; '#' inside quotes is rare in these
    # directives, so a plain split is enough here.
    return line.split("#", 1)[0]


def parse_nginx_t(text: str) -> tuple[list[ServerBlock], dict[str, list[str]]]:
    """Server blocks and ``upstream`` definitions from ``nginx -T`` output. Pure.

    ``nginx -T`` prints every included file (following symlinks), which is
    why it is used instead of grepping sites-enabled/.
    """
    servers: list[ServerBlock] = []
    upstreams: dict[str, list[str]] = {}
    stack: list[str] = []          # block kinds currently open
    cur: ServerBlock | None = None
    cur_up: str | None = None
    for raw in (text or "").splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        # A line may hold several statements: split on ; { } keeping the braces.
        for tok in re.findall(r"[^;{}]+[;{]|}", line):
            tok = tok.strip()
            if tok == "}":
                if stack:
                    kind = stack.pop()
                    if kind == "server" and cur is not None:
                        servers.append(cur)
                        cur = None
                    elif kind == "upstream":
                        cur_up = None
                continue
            if tok.endswith("{"):
                head = tok[:-1].split()
                kind = head[0] if head else ""
                # `nginx -T` prints each file in turn, so a site's server block
                # is not nested inside `http {` in the dump.
                if kind == "server" and cur is None and "upstream" not in stack:
                    cur = ServerBlock()
                elif kind == "upstream" and len(head) > 1:
                    cur_up = head[1]
                    upstreams.setdefault(cur_up, [])
                stack.append(kind)
                continue
            parts = tok.rstrip(";").split()
            if not parts:
                continue
            key, args = parts[0], parts[1:]
            if cur_up is not None and stack and stack[-1] == "upstream":
                if key == "server" and args:
                    upstreams[cur_up].append(args[0])
                continue
            if cur is None:
                continue
            if key == "server_name":
                cur.names.extend(a for a in args if a not in cur.names)
            elif key == "listen" and args:
                cur.listen.append(args[0])
            elif key == "root" and args and args[0] not in cur.roots:
                cur.roots.append(args[0])
            elif key == "fastcgi_pass" and args and args[0] not in cur.fastcgi:
                cur.fastcgi.append(args[0])
            elif key == "proxy_pass" and args and args[0] not in cur.proxy:
                cur.proxy.append(args[0])
    return servers, upstreams


def apache_fpm_versions(conf_text: str) -> list[str]:
    """PHP versions referenced by Apache config (``SetHandler "proxy:unix:/run/
    php/php8.3-fpm.sock|fcgi://localhost"`` or the php8.3-fpm conf). Pure."""
    out: list[str] = []
    for raw in (conf_text or "").splitlines():
        line = raw.split("#", 1)[0]
        if "fpm" not in line:
            continue
        for m in _FPM_SOCK.finditer(line):
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def parse_running_fpm(text: str) -> list[str]:
    """Versions from ``systemctl list-units --type=service --state=running
    --no-legend 'php*-fpm.service'``. Pure."""
    out: list[str] = []
    for line in (text or "").splitlines():
        m = _FPM_UNIT.match(line)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return sorted(out, key=lambda v: tuple(int(x) for x in v.split(".")))


def parse_autoremove(text: str) -> list[str]:
    """Package names ``apt-get -s autoremove`` would remove (``Remv pkg [ver]``). Pure."""
    return [ln.split()[1] for ln in (text or "").splitlines()
            if ln.startswith("Remv ") and len(ln.split()) > 1]


def parse_policy_origin(text: str) -> str | None:
    """Where the installed version came from, from ``apt-cache policy <pkg>``. Pure.

    Returns e.g. ``ppa.launchpadcontent.net/ondrej/php`` or
    ``archive.ubuntu.com jammy-updates``; None if not installed / unknown.
    """
    lines = (text or "").splitlines()
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("***"):
            for nxt in lines[i + 1:]:
                s = nxt.strip()
                if not s or s.startswith("***") or not s[0].isdigit():
                    break
                parts = s.split()
                if len(parts) >= 3 and "://" in parts[1]:
                    url = parts[1].split("://", 1)[1].rstrip("/")
                    if "launchpadcontent.net" in url or "launchpad.net" in url:
                        return url.replace("/ubuntu", "")
                    return f"{url.split('/', 1)[0]} {parts[2].split('/', 1)[0]}"
                if len(parts) >= 2 and parts[1] == "/var/lib/dpkg/status":
                    continue
            return "local (dpkg status only)"
    return None


# --- collectors (read the host; cached per process) -------------------------

@lru_cache(maxsize=1)
def nginx_dump() -> str | None:
    """``nginx -T`` output, or None (no nginx / not root / invalid config)."""
    if not have("nginx"):
        return None
    r = run(["nginx", "-T"], timeout=30)
    return r.out if r.ok and r.out.strip() else None


@lru_cache(maxsize=1)
def apache_conf_text() -> str | None:
    """Enabled Apache config (symlinks followed), or None without Apache."""
    paths: list[str] = []
    for d in ("sites-enabled", "conf-enabled", "mods-enabled"):
        paths += sorted(glob.glob(f"/etc/apache2/{d}/*"))
    if not paths:
        return None
    chunks: list[str] = []
    for p in paths:
        try:
            with open(p, errors="replace") as fh:  # open() follows symlinks
                chunks.append(fh.read())
        except OSError:
            continue
    return "\n".join(chunks)


def running_fpm() -> list[str] | None:
    if not have("systemctl"):
        return None
    r = run(["systemctl", "list-units", "--type=service", "--state=running",
             "--no-legend", "--plain", "php*-fpm.service"], timeout=15)
    return parse_running_fpm(r.out) if r.ok else None


def autoremovable() -> list[str] | None:
    if not have("apt-get"):
        return None
    r = run(["apt-get", "-s", "autoremove"], timeout=120)
    return parse_autoremove(r.out) if r.ok else None


def package_origin(pkg: str) -> str | None:
    if not have("apt-cache"):
        return None
    r = run(["apt-cache", "policy", pkg], timeout=30)
    return parse_policy_origin(r.out) if r.ok else None


# --- findings (pure) ---------------------------------------------------------

def served_summary(servers: list[ServerBlock], upstreams: dict[str, list[str]]) -> list[str]:
    """One line per server block that serves something. Pure."""
    lines: list[str] = []
    for s in servers:
        if not (s.roots or s.fastcgi or s.proxy):
            continue
        names = " ".join(n for n in s.names if n not in ("_", '""')) or "(default)"
        parts = []
        if s.roots:
            parts.append("root " + ", ".join(s.roots))
        php = s.php_versions(upstreams)
        if php:
            parts.append("PHP " + ", ".join(php) + " FPM")
        elif s.fastcgi:
            parts.append("fastcgi " + ", ".join(s.fastcgi))
        if s.proxy:
            parts.append("proxy " + ", ".join(s.proxy))
        lines.append(f"{names} -> " + "; ".join(parts))
    return lines


def referenced_versions(nginx_text: str | None, apache_text: str | None,
                        nginx_present: bool, apache_present: bool) -> set[str] | None:
    """PHP versions the web server config points at, or None when a present
    web server's config could not be read (then "unused" cannot be judged)."""
    if nginx_present and nginx_text is None:
        return None
    if apache_present and apache_text is None:
        return None
    refs: set[str] = set()
    if nginx_text:
        servers, ups = parse_nginx_t(nginx_text)
        for s in servers:
            refs.update(s.php_versions(ups))
    if apache_text:
        refs.update(apache_fpm_versions(apache_text))
    return refs
