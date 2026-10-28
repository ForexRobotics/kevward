"""nginx: apt packages + a couple of cheap config hardening checks."""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin


@register
class NginxPlugin(AptServicePlugin):
    name = "nginx"
    packages = ["nginx", "nginx-core", "nginx-full", "nginx-light"]
    service_unit = "nginx.service"
    kev_terms = ["nginx"]

    def check(self) -> list[Finding]:
        findings = super().check()
        findings.extend(self._config_checks())
        return findings

    def _config_checks(self) -> list[Finding]:
        out: list[Finding] = []
        res = run(["nginx", "-T"], timeout=30)
        if not res.ok:
            return out
        conf = res.out
        if "server_tokens off" not in conf:
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.LOW,
                    title="server_tokens is not disabled",
                    detail="Add `server_tokens off;` to avoid leaking the nginx "
                    "version in responses and error pages.",
                )
            )
        if "ssl_protocols" in conf and ("TLSv1 " in conf or "TLSv1.1" in conf):
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.MEDIUM,
                    title="Deprecated TLS protocols enabled",
                    detail="ssl_protocols appears to allow TLSv1/TLSv1.1. "
                    "Restrict to TLSv1.2 and TLSv1.3.",
                )
            )
        return out
