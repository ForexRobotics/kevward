# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""OpenSSH server: apt packages + config hardening audit (report-only)."""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin


@register
class SshdPlugin(AptServicePlugin):
    name = "sshd"
    packages = ["openssh-server"]
    service_unit = "ssh.service"
    kev_terms = ["openssh"]

    def check(self) -> list[Finding]:
        findings = super().check()
        findings.extend(self._config_checks())
        return findings

    def _config_checks(self) -> list[Finding]:
        out: list[Finding] = []
        # `sshd -T` prints the effective config with normalised keys/values.
        res = run(["sshd", "-T"], timeout=20)
        if not res.ok:
            return out
        cfg = {}
        for line in res.out.splitlines():
            if " " in line:
                k, _, v = line.partition(" ")
                cfg[k.lower()] = v.strip().lower()

        return [
            Finding(
                service=self.name,
                kind=FindingKind.CONFIG,
                severity=sev,
                title=title,
                detail=detail,
            )
            for sev, title, detail in classify_sshd_config(cfg)
        ]


# `sshd -T` normalises these spellings; older/newer OpenSSH use either.
_ROOT_KEY_ONLY = {"prohibit-password", "without-password"}


def classify_sshd_config(cfg: dict[str, str]) -> list[tuple[Severity, str, str]]:
    """Pure classifier over the lower-cased ``sshd -T`` key/value map.

    Returns ``(severity, title, detail)`` tuples; kept free of I/O so it is
    unit-testable without an sshd binary.
    """
    out: list[tuple[Severity, str, str]] = []

    root = cfg.get("permitrootlogin", "")
    if root == "yes":
        out.append((
            Severity.HIGH,
            "PermitRootLogin yes",
            "Root can log in with a password. Set `PermitRootLogin no` and use sudo.",
        ))
    elif root in _ROOT_KEY_ONLY:
        out.append((
            Severity.LOW,
            f"PermitRootLogin {root}",
            "Root can still log in with a key. If nobody needs direct root SSH, "
            "set `PermitRootLogin no` and use sudo.",
        ))
    elif root == "forced-commands-only":
        out.append((
            Severity.INFO,
            "PermitRootLogin forced-commands-only",
            "Root key logins are limited to forced commands; confirm this is intended.",
        ))

    if cfg.get("passwordauthentication") == "yes":
        out.append((
            Severity.MEDIUM,
            "Password authentication enabled",
            "Prefer key-based auth: `PasswordAuthentication no`.",
        ))

    # LoginGraceTime 0 = unauthenticated connections are never timed out.
    # Commonly left behind as the 2024 regreSSHion (CVE-2024-6387) stop-gap;
    # with MaxStartups it lets an attacker hold pre-auth slots open and lock
    # out legitimate admins.
    grace = cfg.get("logingracetime", "")
    if grace == "0":
        maxst = cfg.get("maxstartups", "")
        tail = f" (MaxStartups {maxst})" if maxst else ""
        out.append((
            Severity.MEDIUM,
            "LoginGraceTime 0 (unauthenticated connections never time out)",
            "Pre-auth connections can be held open indefinitely and exhaust "
            f"MaxStartups{tail}, locking out administrators. Often a leftover "
            "regreSSHion (CVE-2024-6387) mitigation; once openssh is patched, set "
            "`LoginGraceTime 30`.",
        ))

    if cfg.get("x11forwarding") == "yes":
        out.append((
            Severity.LOW,
            "X11Forwarding enabled",
            "Disable unless needed: `X11Forwarding no`.",
        ))
    return out
