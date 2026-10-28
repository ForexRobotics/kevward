# Contributing

## Add support for a service in ~5 minutes

kevward auto-discovers any plugin dropped into `kevward/plugins/`. There is
no central registry to edit.

### Case 1 — it's just apt packages

Most services are. Subclass `AptServicePlugin`, declare the package names, done:

```python
# kevward/plugins/redis.py
from ._apt import AptServicePlugin
from ..plugin import register

@register
class RedisPlugin(AptServicePlugin):
    name = "redis"
    packages = ["redis-server", "redis-tools"]
    service_unit = "redis-server.service"
```

You now get security-update detection, minor-upgrade detection and safe
`apply` for free. Add config/hardening checks by overriding `check()` and
calling `super().check()` first (see `nginx.py`, `sshd.py`).

### Case 2 — it's not apt (a language package manager, an API, etc.)

Subclass `ServicePlugin` directly and implement `detect`, `version`, `check`.
Set `supports_apply = False` unless automatic changes are genuinely safe
(see `laravel.py`, `nodejs.py`, `wordpress.py` for report-only examples).

A `check()` returns a list of `Finding` objects:

```python
from ..model import Finding, FindingKind, Severity
Finding(
    service=self.name,
    kind=FindingKind.VULNERABILITY,   # or SECURITY_UPDATE / MINOR_UPGRADE / CONFIG
    severity=Severity.HIGH,
    title="short, human-readable",
    detail="what to do about it",
    cve="CVE-2026-...",               # optional
    ref="package-name",               # set only if apply() can action it
)
```

## Licensing of contributions

kevward is released under **AGPL-3.0-or-later**. To keep the option open to
relicense the project in future (e.g. to a more permissive license), the
maintainer must hold a clear grant over every contribution.

By submitting a pull request you agree to the **Contributor License Agreement**
in [CLA.md](CLA.md): your contribution is licensed to the project under AGPL,
**and** you grant Forex Robotics Co., Ltd. the right to relicense your
contribution under other OSI-approved licenses. You keep your own copyright.

Also sign off each commit to certify origin (Developer Certificate of Origin):

```bash
git commit -s -m "..."    # appends: Signed-off-by: Your Name <you@example.com>
```

A PR without sign-off, or from someone who has not agreed to the CLA, cannot be
merged.

## Ground rules

- **Defensive only.** PRs that add remote scanning, exploitation, "hack-back",
  or anything that acts on a system other than the local host will be declined.
- **No new runtime dependencies** without discussion — the core is stdlib-only
  so it installs anywhere.
- **`check()` must never mutate the system.** Side effects belong in `apply()`.
- Shell out via `kevward.util.run` (argv lists, never shell strings).

## Dev

```bash
pip install -e .
python -m kevward.cli list-plugins
ruff check .
```
