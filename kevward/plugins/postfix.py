# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Postfix: apt packages + relay/exposure config audit (report-only)."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin

MAIN_CF = Path("/etc/postfix/main.cf")


@register
class PostfixPlugin(AptServicePlugin):
    name = "postfix"
    packages = ["postfix"]
    service_unit = "postfix.service"
    kev_terms = ["postfix"]

    def check(self) -> list[Finding]:
        findings = super().check()
        findings.extend(self._config_checks())
        return findings

    def _config_checks(self) -> list[Finding]:
        res = run(["postconf", "-n"], timeout=20)
        if res.ok:
            text = res.out
        else:
            try:
                text = MAIN_CF.read_text(errors="replace")
            except OSError:
                return []
        return [
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=sev,
                title=title,
                detail=detail,
            )
            for sev, title, detail in classify_postfix_config(parse_postconf(text))
        ]


def parse_postconf(text: str) -> dict[str, str]:
    """``postconf -n`` output (or main.cf) -> ``{key: value}``. Pure.

    Skips comments and blank lines and joins main.cf continuation lines
    (lines starting with whitespace).
    """
    cfg: dict[str, str] = {}
    key = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            if key:
                cfg[key] = f"{cfg[key]} {line.strip()}".strip()
            continue
        k, sep, v = line.partition("=")
        if not sep:
            key = None
            continue
        key = k.strip()
        cfg[key] = v.strip()
    return cfg


# Postfix >= 2.10 default when smtpd_relay_restrictions is not set.
_RELAY_DEFAULT = "permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"
_UNAUTH = {"reject_unauth_destination", "defer_unauth_destination"}
_LOOPBACK = {"loopback-only", "localhost", "127.0.0.1", "::1", "[::1]"}


def _tokens(value: str) -> list[str]:
    return [t for t in re.split(r"[\s,]+", value) if t]


def wide_networks(mynetworks: str) -> list[str]:
    """Entries of ``mynetworks`` that are far too wide to trust. Pure.

    Flags any IPv4 range wider than /8, any IPv6 range wider than /16, and
    public ranges wider than /16 (IPv4) or /32 (IPv6). Lookup tables
    (``hash:...``) and hostnames are ignored.
    """
    out = []
    for tok in _tokens(mynetworks):
        cidr = re.sub(r"^\[([^\]]+)\]", r"\1", tok)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            wide = net.prefixlen < 8 or (net.prefixlen < 16 and not net.is_private)
        else:
            wide = net.prefixlen < 16 or (net.prefixlen < 32 and not net.is_private)
        if wide:
            out.append(tok)
    return out


def classify_postfix_config(cfg: dict[str, str]) -> list[tuple[Severity, str, str]]:
    """Pure classifier over ``parse_postconf`` output.

    Returns ``(severity, title, detail)`` tuples. Settings missing from
    ``postconf -n`` take Postfix's defaults.
    """
    out: list[tuple[Severity, str, str]] = []

    relay = _tokens(cfg.get("smtpd_relay_restrictions", _RELAY_DEFAULT))
    recipient = _tokens(cfg.get("smtpd_recipient_restrictions", ""))
    if not _UNAUTH & set(relay + recipient):
        out.append((
            Severity.HIGH,
            "Possible open relay (no reject_unauth_destination)",
            "Neither smtpd_relay_restrictions nor smtpd_recipient_restrictions "
            "rejects mail for foreign domains. Add `reject_unauth_destination` "
            "to smtpd_relay_restrictions.",
        ))

    wide = wide_networks(cfg.get("mynetworks", ""))
    if wide:
        out.append((
            Severity.HIGH,
            "Possible open relay (very wide mynetworks)",
            f"mynetworks trusts {', '.join(wide)}, so those clients may relay "
            "mail anywhere. Limit it to loopback and your own subnets.",
        ))

    iface = _tokens(cfg.get("inet_interfaces", "all").lower())
    if not iface or not set(iface) <= _LOOPBACK:
        out.append((
            Severity.LOW,
            "SMTP listening on the network",
            f"inet_interfaces = {' '.join(iface) or 'all'}. A send-only host "
            "does not need this: set `inet_interfaces = loopback-only`.",
        ))

    level = cfg.get("smtp_tls_security_level", "").lower()
    legacy_tls = cfg.get("smtp_use_tls", "").lower() == "yes"
    if level in ("", "none") and not legacy_tls:
        out.append((
            Severity.LOW,
            "No TLS on outbound SMTP",
            "smtp_tls_security_level is unset or none, so mail leaves in "
            "plaintext. Set `smtp_tls_security_level = may`.",
        ))
    return out
