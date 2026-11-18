# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""nginx: apt packages + a couple of cheap config hardening checks."""

from __future__ import annotations

from ..model import Finding, FindingKind, Severity
from ..plugin import register
from . import _webserve as ws
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
        conf = ws.nginx_dump()  # `nginx -T`, shared with the php plugin (#85)
        if conf is None:
            return out
        servers, upstreams = ws.parse_nginx_t(conf)
        served = ws.served_summary(servers, upstreams)
        if served:
            out.append(
                Finding(
                    service=self.name,
                    kind=FindingKind.CONFIG,
                    severity=Severity.INFO,
                    title=f"nginx serves {len(served)} site(s)",
                    detail="; ".join(served)[:1000],
                )
            )
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
