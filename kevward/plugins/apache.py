"""Apache HTTP Server (httpd): apt packages + a cheap config hardening check."""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from ..util import run
from ._apt import AptServicePlugin


@register
class ApachePlugin(AptServicePlugin):
    name = "apache"
    packages = ["apache2", "apache2-bin"]
    service_unit = "apache2.service"
    # "http server" targets KEV's "Apache / HTTP Server" without matching the
    # many other Apache Foundation products (Struts, Tomcat, ActiveMQ, ...).
    kev_terms = ["http server"]

    def check(self) -> list[Finding]:
        findings = super().check()
        findings.extend(self._config_checks())
        return findings

    def _config_checks(self) -> list[Finding]:
        out: list[Finding] = []
        # `apache2ctl -S` dumps the parsed vhost/config; we only need to know
        # whether ServerTokens/ServerSignature expose version info.
        res = run(["apache2ctl", "-t", "-D", "DUMP_RUN_CFG"], timeout=20)
        text = (res.out + res.err).lower()
        if res.ok and "servertokens" in text and "prod" not in text:
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.LOW,
                    title="ServerTokens may leak version info",
                    detail="Set `ServerTokens Prod` and `ServerSignature Off` to "
                    "avoid advertising the Apache/OS version.",
                )
            )
        return out
