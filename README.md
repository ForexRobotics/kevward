# patchward

[![CI](https://github.com/ForexRobotics/patchward/actions/workflows/ci.yml/badge.svg)](https://github.com/ForexRobotics/patchward/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Defensive server hardening & patch automation for Ubuntu.**

patchward runs *on a server* and answers three questions a sysadmin asks every
morning:

1. **What on this box is vulnerable or out of date?** — pending security
   updates and minor upgrades for the base system (apt), web servers
   (nginx, Apache), databases (MySQL, MariaDB, PostgreSQL, Redis) and
   php/openssh/ufw, plus dependency advisories for Composer/Laravel,
   Node.js/npm and WordPress.
2. **Who is attacking me?** — a time-ordered view of banned / probing source
   IPs from fail2ban and sshd auth logs.
3. **Of everything being exploited in the wild right now, does any of it apply
   to me?** — cross-references the [CISA KEV catalog][kev] (known
   *actively-exploited* CVEs) against software detected on the host.

It can **report**, and — only when you explicitly opt in — **apply** security
patches and **schedule a reboot** inside a maintenance window.

> **Scope: this is a defensive tool.** It only inspects and patches the host it
> runs on. It contains no capability to scan, access, or act against any remote
> system, and none will be accepted. "Active defense" here means staying ahead
> of attackers on your own infrastructure — not hacking back, which in Japan
> remains restricted to designated authorities under the 2026
> サイバー対処能力強化法 and is otherwise an offence under the 不正アクセス禁止法.

[kev]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Install

```bash
git clone https://github.com/ForexRobotics/patchward
cd patchward
pip install .            # or: pipx install .
```

**Requires Python 3.10+** (Ubuntu 22.04 and newer). The only dependency is
`tomli`, and only on Python 3.10 — on 3.11+ the standard library's `tomllib`
is used and patchward has no dependencies at all. Optional host tools are
detected at runtime: `apt`, `composer`, `npm`, `wp` (wp-cli), `fail2ban`,
`logwatch`.

To make `patchward` available to root (needed for `report`/`apply`) when
installed in a virtualenv, symlink it onto the system path:

```bash
sudo python3 -m venv /opt/patchward
sudo /opt/patchward/bin/pip install .
sudo ln -sf /opt/patchward/bin/patchward /usr/local/bin/patchward
```

### Supported services

| Area        | Services |
|-------------|----------|
| Base system | apt (host-wide updates, reboot detection) |
| Web servers | nginx, Apache (`apache2`) |
| Databases   | MySQL, MariaDB, PostgreSQL, Redis |
| Runtimes    | PHP, Node.js |
| Apps        | Composer/Laravel, WordPress *(report-only)* |
| Access      | OpenSSH (sshd), ufw |

Any service not installed is silently skipped. Adding another is one file —
see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```bash
patchward check                 # report findings, change nothing (default)
patchward check -s nginx -s php # limit to specific services
patchward trends                # actively-exploited CVEs relevant to this host
patchward report --trends       # write an HTML posture + attacker-IP report
patchward apply                 # DRY RUN: show what would be patched
sudo patchward apply --yes      # actually apply security updates
sudo patchward apply --yes --minor --reboot   # +minor upgrades, +schedule reboot
sudo patchward schedule-reboot --window 04:00
patchward list-plugins
```

### Safety model

- **Read-only by default.** `check`, `report`, `trends` never change anything.
- **`apply` is explicit.** Without `--yes` it is a dry run. Security updates
  only; minor upgrades need `--minor` or policy.
- **Reboots are double-gated.** They happen only when `allow_reboot = true`
  *and* a reboot is requested (`--reboot` / `schedule-reboot`).
- **Risky services are report-only.** Composer/Laravel, Node.js and WordPress
  are audited but never auto-updated — a dependency bump is the app owner's
  call, not a cron job's.

## Configuration

Copy `config.example.toml` to `/etc/patchward/config.toml`. All defaults are
conservative; see that file for every option, including where to point the
Composer/Laravel/Node/WordPress scanners.

## Scheduling

Install the units in `systemd/`:

```bash
sudo cp systemd/patchward-report.* /etc/systemd/system/
sudo systemctl enable --now patchward-report.timer    # daily read-only report
# Only after you trust it:
sudo cp systemd/patchward-apply.* /etc/systemd/system/
sudo systemctl enable --now patchward-apply.timer      # weekly security patching
```

## Adding a service

Drop one file in `patchward/plugins/` — it is auto-discovered. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the 5-minute guide.

## Security

Found a vulnerability in patchward? Please report it privately — see
[SECURITY.md](SECURITY.md). Don't open a public issue for security problems.

## Acknowledgments

The initial release was designed and written in pair-programming sessions with
**Claude** (Anthropic's AI assistant). This is not an endorsement or an official
Anthropic project — just a thank-you for the help. All design decisions and
responsibility for the code rest with the maintainer.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

patchward is strong copyleft, including over a network: if you run a modified
version as a service, you must offer its source to that service's users
(AGPL §13). Copyright © 2026 Forex Robotics Co., Ltd. (Forex Robotics 株式会社);
contributions are accepted under a CLA so the project can be relicensed in
future if the maintainer chooses (see [CONTRIBUTING.md](CONTRIBUTING.md)).
