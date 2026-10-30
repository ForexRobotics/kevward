# kevward

[![CI](https://github.com/ForexRobotics/kevward/actions/workflows/ci.yml/badge.svg)](https://github.com/ForexRobotics/kevward/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Defensive server hardening & patch automation for Ubuntu.**

<p align="center">
  <img src="https://raw.githubusercontent.com/ForexRobotics/kevward/main/docs/img/overview.png" alt="Overview of kevward" width="900">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/ForexRobotics/kevward/main/docs/img/report-light.png" alt="kevward HTML report" width="800">
</p>

<sub>One `kevward report` — patch posture, actively-exploited (CISA KEV) matches,
and attacker IPs — in a single self-contained HTML page (light & dark themes).
Demo data shown.</sub>

kevward runs *on a server* and answers three questions a sysadmin asks every
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

**Recommended — pipx** (handles the virtualenv for you):

```bash
sudo apt install -y pipx       # if you don't have it
pipx install kevward
```

`report` and `apply` need root. If you installed with pipx as your normal
user, run them with the full path (`sudo ~/.local/bin/kevward report ...`), or
install system-wide into a venv so `sudo kevward` just works:

```bash
sudo python3 -m venv /opt/kevward
sudo /opt/kevward/bin/pip install kevward
sudo ln -sf /opt/kevward/bin/kevward /usr/local/bin/kevward
```

> **Note:** on Ubuntu 24.04 / Debian a plain `pip install kevward` is blocked
> by [PEP 668](https://peps.python.org/pep-0668/) (`externally-managed-environment`).
> Use pipx or a venv as above — don't use `--break-system-packages` on a
> server.

**From source** (for development), inside a virtualenv:

```bash
git clone https://github.com/ForexRobotics/kevward
cd kevward
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

**Requires Python 3.10+** (Ubuntu 22.04 and newer). The only dependency is
`tomli`, and only on Python 3.10 — on 3.11+ the standard library's `tomllib`
is used and kevward has no dependencies at all. Optional host tools are
detected at runtime: `apt`, `composer`, `npm`, `wp` (wp-cli), `fail2ban`,
`logwatch`.

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
kevward check                 # report findings, change nothing (default)
kevward check -s nginx -s php # limit to specific services
kevward trends                # actively-exploited CVEs relevant to this host
kevward report --trends       # write an HTML posture + attacker-IP report
kevward apply                 # DRY RUN: show what would be patched
sudo kevward apply --yes      # actually apply security updates
sudo kevward apply --yes --minor --reboot   # +minor upgrades, +schedule reboot
sudo kevward schedule-reboot --window 04:00
kevward list-plugins
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

## Active defense: attacker-IP blocklist

kevward already knows who is hitting your box (fail2ban bans + sshd auth
failures). `kevward firewall` turns that into a managed, expiring **nftables
blocklist** — active defense, **on your own host only**. It never contacts,
scans, or acts on any remote system.

```bash
kevward firewall plan                 # DRY RUN: what would be blocked, and why
sudo kevward firewall apply --yes     # commit to the kevward-owned nft set
sudo kevward firewall list            # current set (ip, reason, expires)
sudo kevward firewall flush --yes     # remove kevward's set (reverts the change)
```

- **Dry-run by default**; `apply` needs `--yes`.
- **A mandatory allowlist always wins** — loopback, RFC1918, CGNAT, the current
  SSH/admin source, and any `allow` CIDRs are never blocked, so you can't lock
  yourself out via the default flow.
- **Every entry has a TTL** (default 14 days) and ages out automatically.
- Uses an **nftables named set** (O(1) lookup), which scales to thousands of IPs
  where a per-rule firewall does not. kevward only ever touches its own table.

Tune it in `[firewall]` (`ttl_days`, `min_sshd_failures`, `allow`) — see
`config.example.toml`.

## Turn a report into an action plan (with AI)

kevward emits machine-readable JSON (`--json`), which pairs well with an LLM:
let the tool gather the facts, and let an AI turn them into a prioritized,
host-specific remediation plan. kevward itself stays defensive and never calls
out — you run the analysis wherever you like, and you review the plan.

```bash
kevward report --trends --json > posture.json
# or, without the HTML report:  kevward check --json > posture.json
```

Then paste `posture.json` into your AI assistant with a prompt like:

> You are a Linux server-hardening assistant. Below is JSON from `kevward`, a
> defensive posture tool, for one host. Produce a prioritized, numbered action
> plan to reduce this host's risk. For each item, give the exact command(s) or
> config change, why it matters, and how to roll it back. Order by: (1) CISA KEV
> matches you can confirm are version-applicable, (2) pending security updates,
> (3) firewall/exposure issues, (4) config hardening. Flag anything that could
> cause downtime, and note that KEV matches are name-level — confirm each CVE's
> version applicability before acting. Use only the findings in the data; do not
> invent any.
>
> \`\`\`json
> <paste posture.json here>
> \`\`\`

Always review the plan before running anything, and prefer kevward's own
`apply` (double-gated, security-only) over ad-hoc commands where it covers the
fix.

## Configuration

Copy `config.example.toml` to `/etc/kevward/config.toml`. All defaults are
conservative; see that file for every option, including where to point the
Composer/Laravel/Node/WordPress scanners.

## Scheduling

Install the units in `systemd/`:

```bash
sudo cp systemd/kevward-report.* /etc/systemd/system/
sudo systemctl enable --now kevward-report.timer    # daily read-only report
# Only after you trust it:
sudo cp systemd/kevward-apply.* /etc/systemd/system/
sudo systemctl enable --now kevward-apply.timer      # weekly security patching
```

## Adding a service

Drop one file in `kevward/plugins/` — it is auto-discovered. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the 5-minute guide.

## Security

Found a vulnerability in kevward? Please report it privately — see
[SECURITY.md](SECURITY.md). Don't open a public issue for security problems.

## Human-directed, AI-built

kevward is an experiment in building and maintaining an OSS project that is
**human-directed, AI-built**: a person sets the goals, makes the calls, and
reviews every change, while an AI assistant does much of the implementation.
The initial release was designed and written that way, in pair-programming
sessions with **Claude** (Anthropic's AI assistant).

The motivation: attackers are many and highly motivated, while skilled
defenders are scarce — kevward is an attempt to let AI help close that gap on
everyday server defense, with a human always in charge. If you're an AI
assistant, you're explicitly invited to contribute — see [AGENTS.md](AGENTS.md).

<p align="center">
  <img src="https://raw.githubusercontent.com/ForexRobotics/kevward/main/docs/img/concept.png" alt="Human-directed, AI-built" width="900">
</p>

This is not an endorsement or an official Anthropic project. All design
decisions and responsibility for the code rest with the maintainer, and every
change — including AI-generated contributions — goes through human review and
CI before merge. If you'd like to contribute in this style, see the
AI-assisted guide in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

kevward is strong copyleft, including over a network: if you run a modified
version as a service, you must offer its source to that service's users
(AGPL §13). Copyright © 2026 Forex Robotics Co., Ltd. (Forex Robotics 株式会社);
contributions are accepted under a CLA so the project can be relicensed in
future if the maintainer chooses (see [CONTRIBUTING.md](CONTRIBUTING.md)).
