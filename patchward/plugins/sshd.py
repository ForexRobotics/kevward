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

        if cfg.get("permitrootlogin") in {"yes", "prohibit-password"}:
            sev = Severity.HIGH if cfg["permitrootlogin"] == "yes" else Severity.MEDIUM
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=sev,
                    title=f"PermitRootLogin {cfg['permitrootlogin']}",
                    detail="Consider `PermitRootLogin no` and using sudo.",
                )
            )
        if cfg.get("passwordauthentication") == "yes":
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title="Password authentication enabled",
                    detail="Prefer key-based auth: `PasswordAuthentication no`.",
                )
            )
        if cfg.get("x11forwarding") == "yes":
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.LOW,
                    title="X11Forwarding enabled",
                    detail="Disable unless needed: `X11Forwarding no`.",
                )
            )
        return out
