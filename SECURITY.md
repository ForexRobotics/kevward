# Security Policy

kevward is a defensive security tool, so we take vulnerabilities in it
seriously — a flaw here could affect the servers people run it on.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred: use GitHub's private vulnerability reporting —
**Security → Report a vulnerability** on
<https://github.com/ForexRobotics/kevward/security/advisories>.

Alternatively, email **security@forexrobotics.jp** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal PoC if possible),
- the kevward version (`kevward --version`) and OS.

We aim to acknowledge reports within **5 business days** and to agree a
disclosure timeline with you. We support coordinated disclosure and will credit
reporters who wish to be named.

## Scope

In scope: the kevward code itself — e.g. command injection, privilege
escalation via the `apply`/reboot paths, unsafe file handling, or a report that
leaks sensitive host data.

Out of scope: vulnerabilities in the third-party tools kevward invokes (apt,
composer, npm, wp-cli, fail2ban, ...) — report those upstream. kevward is
designed to act only on the local host, and reports of "it can't scan other
machines" are intended behaviour, not bugs.

The one way in from outside is `kevward ssh-gate`, and it is off by default.
It is the forced command of an SSH key that a host owner adds on purpose
(`[ssh_gate] enabled = true`). It never connects anywhere. With the `read`
role it only returns reports and the config. With the `operate` role (sudo,
exact-match sudoers line), `config.set` can change only an allowlist of keys
that cannot weaken detection or protection. Every change is logged to syslog
and to `/var/lib/kevward/ssh-gate-changes.jsonl`, and is shown in the report
for 7 days. A way around those limits through the gate — writing a key outside
the allowlist, writing outside the config file, or running anything but the
listed ops — is in scope.

## Verifying a release

Every release on PyPI is built and uploaded by the `publish.yml` workflow in
this repository via Trusted Publishing (OIDC; no stored PyPI token), and PyPI
records a signed provenance attestation for each file. To check that a file
you are about to install came from this repository's workflow:

```sh
python3 -m venv /tmp/kv && /tmp/kv/bin/pip install pypi-attestations
/tmp/kv/bin/pypi-attestations verify pypi \
  --repository https://github.com/ForexRobotics/kevward \
  pypi:kevward-X.Y.Z-py3-none-any.whl
```

Replace `X.Y.Z` with the version. The same check can be run for the sdist
(`pypi:kevward-X.Y.Z.tar.gz`). The provenance is also shown on each file's
page on <https://pypi.org/project/kevward/#files>.

Release hygiene on the repository side:

- release tags (`v*`) cannot be deleted or moved;
- `main` only changes through pull requests that pass CI;
- workflow actions are pinned to full commit SHAs.
- release tags are created by the `release-tag.yml` workflow when a
  `release/X.Y.Z` pull request is merged, only after the branch name,
  `pyproject.toml`, `kevward/__init__.py` and the CHANGELOG all say `X.Y.Z`;
- PyPI uploads come only from the `pypi` environment, which accepts `v*` tags
  only.

## Supported versions

During the `0.x` series, only the latest released version receives security
fixes.
