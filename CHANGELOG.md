# Changelog

## 0.4.1

- **Fix `kevward harden list` false negative for `ip_options_table`.** Querying
  nftables needs root, so an unprivileged `harden list` was reporting the
  kevward table as absent (`False`) when it actually existed. Detection is now
  tri-state — `True` (present) / `False` (confirmed absent) / `unknown (run as
  root)` — and non-root runs print a hint instead of a misleading `False`. The
  mitigation itself was always applied correctly; only the status readout was
  wrong.
- **`kevward harden revert` no longer overstates re-enabling MPTCP.** It now
  removes only kevward's sysctl drop-in and re-evaluates all drop-ins
  (`sysctl --system`) rather than forcing `net.mptcp.enabled=1`, then reports
  the real effective value — so a hand-written drop-in that still disables MPTCP
  is reported honestly.

## 0.4.0

Two additions aimed at the attacker/defender gap: safer blocklisting, and
reversible interim mitigations for the window before a kernel fix ships.

- **`kevward firewall` optional DNSBL cross-check (opt-in).** `--check-dnsbl`
  looks up only the top-N block candidates against a DNS blocklist to reduce
  false positives. `enrich` (default) annotates the plan with each IP's verdict;
  `--require-reputation` (confirm) blocks only IPs the DNSBL flags as malicious.
  Off by default, so kevward still makes no network call unless asked. A minimal
  stdlib UDP DNS query to a configurable resolver (`--dnsbl-resolver`, since
  DNSBLs rate-limit per resolver and public ones are blocked by Spamhaus), with
  a Spamhaus-DQS-capable `--dnsbl-zone`, a TTL cache, and strict **fail-soft**
  (blocked-resolver codes / timeouts are "unknown" and never block). The
  allowlist still always wins. (#4)
- **`kevward harden` (prototype) — host hardening checks + reversible interim
  mitigations, local host only.** `harden check` reports posture (running vs
  newest-installed kernel + reboot-required, key security sysctls, Ubuntu
  Livepatch status, public TCP listeners). `harden apply --yes` applies opt-in,
  kevward-owned, reversible mitigations: `--mptcp-off` (sysctl drop-in) and
  `--drop-ip-options` (drop inbound IPv4 packets carrying IP options via an
  nftables table). The ip-options rule is made **reboot-persistent** by a tiny
  kevward-owned systemd unit that re-applies it on boot — so interim mitigations
  survive a reboot. `harden list` shows state; `harden revert --yes` removes
  exactly what kevward added. Dry-run by default; never touches SSH or ufw;
  motivated by CVE-2026-98432. (#6)

## 0.3.0

- **`kevward firewall` — active-defense blocklist (local host only).** Turns the
  attacker IPs kevward already collects for the report (fail2ban bans + sshd auth
  failures) into a managed, expiring nftables blocklist. `plan` is a dry run
  (default); `apply --yes` commits; `list` / `flush` manage kevward's own set.
  Every entry carries a TTL, and a mandatory allowlist (loopback, RFC1918, CGNAT,
  the current SSH/admin source, and any configured CIDRs) makes self-block
  impossible by default. An nftables named set (O(1) lookup) scales to thousands
  of IPs where per-rule UFW does not. Configurable via a `[firewall]` section.
  Still strictly defensive: it only filters ingress on the host it runs on and
  never touches any remote system. (#4)
- This release also carries the 0.2.3 changes below (which were not published to
  PyPI): `AGENTS.md` and the project mission in the README.

## 0.2.3

- Added `AGENTS.md`: a guide for AI coding assistants — the project's mission
  (help close the attacker/defender gap), the hard rules, the code map, and the
  contribution workflow. The README now links it and states that mission.

## 0.2.2

- **Documented the AI-assisted workflow.** The README now shows how to turn a
  `--json` report into a prioritized remediation plan with an LLM, and frames
  the project as *human-directed, AI-built*. CONTRIBUTING adds
  AI-assisted contribution prompts for adding a service plugin, a new distro
  backend, and version-level KEV matching. No code changes.

## 0.2.1

- **Fixed the install instructions.** `pip install .` fails on Ubuntu 24.04 /
  Debian with `externally-managed-environment` (PEP 668). The README now leads
  with `pipx install kevward`, documents the system-wide venv install for
  `sudo kevward`, and shows the from-source dev install inside a venv.
- Added a screenshot of the HTML report to the README (`docs/img/`).

## 0.2.0

- **Renamed the project from `patchward` to `kevward`** ahead of its first PyPI
  release (the name `patchward` was already taken on PyPI by an unrelated
  project). The command, Python package, config paths (`/etc/kevward`,
  `/var/log/kevward`, `/var/cache/kevward`) and systemd units
  (`kevward-report.*`, `kevward-apply.*`) are all renamed. Existing
  installations should reinstall under the new name.
- Added a GitHub Actions workflow to publish to PyPI via Trusted Publishing on
  tagged releases.

## 0.1.3

- **Python 3.10 support** (Ubuntu 22.04 LTS). The 3.11-only `StrEnum`,
  `tomllib` and `datetime.UTC` are replaced with 3.10-compatible equivalents;
  `tomli` is pulled in automatically on 3.10 only. Tested on 3.10–3.13.
- **New service plugins**: Apache HTTP Server, MySQL, MariaDB, PostgreSQL and
  Redis — apt-managed, with CISA KEV term mapping. Apache also gets a
  ServerTokens hardening check.
- README: documented supported services, the Python requirement and the
  virtualenv/system-path install.

## 0.1.2

- **KEV matching no longer uses the free-text vulnerability name**, only the
  vendor and product. A CVE whose description happens to mention a technology
  (e.g. a Zimbra or Juniper advisory with "PHP" in its name) no longer
  false-matches a host that merely runs that technology.

## 0.1.1

- **KEV trends scoped to detected software.** CISA KEV matching now uses the
  products actually present on the host (via each plugin's `kev_terms`) instead
  of a broad built-in keyword list, so results no longer include appliances and
  products the host doesn't run (Fortinet, Cisco, Citrix, VMware, ...).
- Plugins gained an optional `kev_terms` attribute; `plugin.detected_kev_terms()`
  collects terms for present services.
- `trends` output and the HTML report now state that matches are name-level and
  that version applicability must be confirmed per CVE.

## 0.1.0

- Initial public release.
