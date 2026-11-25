# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""BIND9 (#132): apt packages + open-resolver check.

The KEV term is ``isc:bind`` (vendor:product) so plain "bind" does not match
unrelated products.

On top of the apt checks, ``named-checkconf -p`` (read-only: it parses the
config and prints it in canonical form) is checked for an open resolver:
MEDIUM when recursion is on and the effective recursion ACL is ``any``, so
anyone can use the server for DNS amplification. The effective ACL follows
the BIND documentation: ``allow-recursion``, else ``allow-query-cache``, else
``allow-query``, else the default ``localnets; localhost;`` (not open).
Each ``view`` inherits ``options`` and is checked on its own.
"""

from __future__ import annotations

import re

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{};]|[^\s{};"]+')
OPEN_ACL = {"any", "0.0.0.0/0", "::/0"}
_ACL_KEYS = ("allow-recursion", "allow-query-cache", "allow-query")


def _tokens(text: str) -> list[str]:
    text = re.sub(r"(?m)(#|//).*$", "", text or "")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return [t[1:-1] if t.startswith('"') else t for t in _TOKEN.findall(text)]


def _block(tokens: list[str], i: int) -> tuple[list, int]:
    """Parse statements from ``tokens[i]`` up to the matching ``}``.
    Each statement is ``(words, children or None)``."""
    out: list = []
    words: list[str] = []
    while i < len(tokens):
        t = tokens[i]
        if t == "}":
            return out, i + 1
        if t == ";":
            if words:
                out.append((words, None))
            words = []
            i += 1
        elif t == "{":
            children, i = _block(tokens, i + 1)
            out.append((words, children))
            words = []
            if i < len(tokens) and tokens[i] == ";":
                i += 1
        else:
            words.append(t)
            i += 1
    if words:
        out.append((words, None))
    return out, i


def parse_conf(text: str) -> list:
    """named.conf text (e.g. ``named-checkconf -p``) -> statement tree. Pure."""
    tree, _ = _block(_tokens(text), 0)
    return tree


def _settings(statements: list) -> dict[str, object]:
    """``recursion`` and the ACL statements of one block."""
    out: dict[str, object] = {}
    for words, children in statements:
        if not words:
            continue
        key = words[0].lower()
        if key == "recursion" and len(words) > 1:
            out[key] = words[1].lower()
        elif key in _ACL_KEYS and children is not None:
            out[key] = [" ".join(w).lower() for w, _ in children]
    return out


def _open(settings: dict[str, object]) -> bool:
    if settings.get("recursion", "yes") in {"no", "false", "0"}:
        return False
    for key in _ACL_KEYS:
        if key in settings:
            # A negated element ("! any") is a different string, so it never counts.
            return any(e in OPEN_ACL for e in settings[key])
    return False


def open_resolvers(text: str) -> list[str]:
    """Names of the scopes (``options`` or ``view <name>``) that are open
    resolvers. Pure."""
    tree = parse_conf(text)
    options: dict[str, object] = {}
    for words, children in tree:
        if words and words[0].lower() == "options" and children is not None:
            options = _settings(children)
    views = [(w, c) for w, c in tree if w and w[0].lower() == "view" and c is not None]
    if not views:
        return ["options"] if _open(options) else []
    out = []
    for words, children in views:
        if _open({**options, **_settings(children)}):
            out.append(f"view {words[1] if len(words) > 1 else '?'}")
    return out


@register
class Bind9Plugin(AptServicePlugin):
    name = "bind9"
    packages = ["bind9"]
    service_unit = "named.service"
    kev_terms = ["isc:bind"]

    def check(self) -> list[Finding]:
        findings = super().check()
        res = run(["named-checkconf", "-p"], timeout=30)
        if not res.ok:
            return findings
        findings.extend(
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=Severity.MEDIUM,
                title=f"BIND9 is an open resolver ({scope})",
                detail="Recursion is allowed for any client, so the server can be "
                "abused for DNS amplification. Limit it, e.g. "
                "`allow-recursion { localnets; localhost; };`, or set `recursion no;` "
                "on an authoritative-only server.",
            )
            for scope in open_resolvers(res.out)
        )
        return findings
