"""Plugin contract and registry.

Adding support for a new service is intentionally a one-file job: subclass
``ServicePlugin`` (or ``AptServicePlugin`` for apt-managed packages), drop the
module into ``patchward/plugins/``, and it is auto-discovered at runtime. No
central list to edit.
"""

from __future__ import annotations

import abc
import importlib
import pkgutil
from collections.abc import Iterable

from .model import ActionResult, Finding, ServiceReport


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

    #: Substrings used to match this service's upstream in threat-intel feeds
    #: (e.g. CISA KEV). Only consulted when the service is detected on the host,
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
    def report(self, do_apply: bool, dry_run: bool) -> ServiceReport:
        if not self.detect():
            return ServiceReport(service=self.name, present=False)
        rep = ServiceReport(service=self.name, present=True, version=self.version())
        try:
            rep.findings = self.check()
            if do_apply and self.supports_apply:
                actionable = [f for f in rep.findings if f.ref is not None]
                rep.actions = self.apply(actionable, dry_run=dry_run)
        except Exception as exc:  # pragma: no cover - defensive
            rep.error = f"{type(exc).__name__}: {exc}"
        return rep


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
    """Import every module under patchward.plugins so decorators run."""
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
