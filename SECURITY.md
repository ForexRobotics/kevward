# Security Policy

patchward is a defensive security tool, so we take vulnerabilities in it
seriously — a flaw here could affect the servers people run it on.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred: use GitHub's private vulnerability reporting —
**Security → Report a vulnerability** on
<https://github.com/ForexRobotics/patchward/security/advisories>.

Alternatively, email **security@forexrobotics.jp** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal PoC if possible),
- the patchward version (`patchward --version`) and OS.

We aim to acknowledge reports within **5 business days** and to agree a
disclosure timeline with you. We support coordinated disclosure and will credit
reporters who wish to be named.

## Scope

In scope: the patchward code itself — e.g. command injection, privilege
escalation via the `apply`/reboot paths, unsafe file handling, or a report that
leaks sensitive host data.

Out of scope: vulnerabilities in the third-party tools patchward invokes (apt,
composer, npm, wp-cli, fail2ban, ...) — report those upstream. patchward is
designed to act only on the local host; it has no remote-attack surface by
design, and reports of "it can't scan other machines" are intended behaviour,
not bugs.

## Supported versions

During the `0.x` series, only the latest released version receives security
fixes.
