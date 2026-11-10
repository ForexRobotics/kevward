# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Plugin contract and registry.

Adding support for a new service is intentionally a one-file job: subclass
``ServicePlugin`` (or ``AptServicePlugin`` for apt-managed packages), drop the
module into ``kevward/plugins/``, and it is auto-discovered at runtime. No
central list to edit.
"""

from __future__ import annotations

import abc
import importlib
import pkgutil
from collections.abc import Iterable

from .model import ActionResult, Finding, FindingKind, ServiceReport


class ServicePlugin(abc.ABC):
    """Base contract every service plugin implements.

    Lifecycle per run: ``detect`` -> ``version`` -> ``check`` -> (optional)
    ``apply``. Plugins must be side-effect-free in everything except
    ``apply``.
    """

    #: Short stable id, e.g. "nginx". Used in config and CLI filters.
    name: str = ""

    #: If False, ``apply`` is never called for this plugin regardless of flags.
    #: Use for report-only services (e.g. Laravel/composer) where automatic
    #: changes are too risky to make unattended.
    supports_apply: bool = True

    #: Whole-word terms matched against the vendor/product in threat-intel
    #: feeds (e.g. CISA KEV); ``vendor:product`` pins both. Only consulted
    #: when the service is detected on the host,
    #: which keeps trend matches relevant instead of flooding them with
    #: appliances/products this host doesn't run. Empty = not matched by name.
    kev_terms: list[str] = []

    @abc.abstractmethod
    def detect(self) -> bool:
        """Is this service installed / relevant on this host?"""

    def version(self) -> str | None:  # noqa: D401
        """Best-effort installed version string, or None."""
        return None

    @abc.abstractmethod
    def check(self) -> list[Finding]:
        """Return findings without changing anything."""

    def apply(self, findings: list[Finding], dry_run: bool) -> list[ActionResult]:
        """Action the given findings. Default: nothing to do."""
        return []

    # --- convenience, used by the engine ---------------------------------
    def report(
        self,
        do_apply: bool,
        dry_run: bool,
        apply_security: bool = True,
        apply_minor: bool = False,
        claimed: set[str] | None = None,
    ) -> ServiceReport:
        """Check, then (optionally) apply what policy allows.

        ``claimed`` is shared across plugins within one run: package refs an
        earlier plugin already handed to ``apply()`` are skipped here and the
        refs this plugin applies are added, so a package owned by two plugins
        (e.g. ``apache`` and the host-wide ``apt``) is listed and installed once.
        """
        if not self.detect():
            return ServiceReport(service=self.name, present=False)
        rep = ServiceReport(service=self.name, present=True, version=self.version())
        try:
            rep.findings = self.check()
            if do_apply and self.supports_apply:
                actionable = select_actionable(
                    rep.findings, apply_security=apply_security, apply_minor=apply_minor
                )
                if claimed is not None:
                    actionable = [f for f in actionable if f.ref not in claimed]
                    claimed.update(f.ref for f in actionable if f.ref)
                if actionable:
                    rep.actions = self.apply(actionable, dry_run=dry_run)
        except Exception as exc:  # pragma: no cover - defensive
            rep.error = f"{type(exc).__name__}: {exc}"
        return rep


def select_actionable(
    findings: Iterable[Finding], apply_security: bool, apply_minor: bool
) -> list[Finding]:
    """Findings that policy allows ``apply()`` to act on.

    Only package changes are actionable (they carry a ``ref``), and each kind is
    gated by its own policy switch: security updates by ``apply_security``,
    minor upgrades by ``apply_minor``. Anything else is never applied.
    """
    allowed: set[FindingKind] = set()
    if apply_security:
        allowed.add(FindingKind.SECURITY_UPDATE)
    if apply_minor:
        allowed.add(FindingKind.MINOR_UPGRADE)
    return [f for f in findings if f.ref is not None and f.kind in allowed]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, type[ServicePlugin]] = {}


def register(cls: type[ServicePlugin]) -> type[ServicePlugin]:
    """Class decorator to register a plugin."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty `name`")
    _REGISTRY[cls.name] = cls
    return cls


def discover() -> dict[str, type[ServicePlugin]]:
    """Import every module under kevward.plugins so decorators run."""
    from . import plugins  # local import to avoid cycles

    for mod in pkgutil.iter_modules(plugins.__path__):
        importlib.import_module(f"{plugins.__name__}.{mod.name}")
    return dict(_REGISTRY)


def load(only: Iterable[str] | None = None) -> list[ServicePlugin]:
    """Instantiate all (or a filtered subset of) registered plugins."""
    registry = discover()
    names = list(registry) if only is None else [n for n in only if n in registry]
    return [registry[n]() for n in names]


def detected_kev_terms(only: Iterable[str] | None = None) -> list[str]:
    """Threat-intel search terms for software actually present on this host.

    Always includes the OS itself ("linux"/"ubuntu"); adds each detected
    plugin's ``kev_terms``. Used to scope KEV/trend matching to what the host
    really runs. ``detect()`` is cheap, so calling this is inexpensive.
    """
    terms: set[str] = {"linux", "ubuntu"}
    for p in load(only):
        try:
            if p.detect():
                terms.update(p.kev_terms)
        except Exception:  # pragma: no cover - defensive
            continue
    return sorted(terms)
