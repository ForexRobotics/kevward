# Changelog

## Unreleased

- **Cold hosts resolve the KEV table in one run (#66).** Uncached Ubuntu CVE
  lookups now run 4 at a time (`[trends] fetch_workers`, 1–16), still inside
  the time budget, and `kevward trends --warm-cache` does one long pass (up to
  10 min) to fill the cache after install. Exit code 1 if rows are still
  unchecked or the cache is not writable.
- **Release integrity (#115).** GitHub Actions in CI and the publish workflow
  are pinned to full commit SHAs (Dependabot keeps them current) and moved to
  their Node 24 majors; checkouts no longer keep the token on disk.
  SECURITY.md now explains how to verify a PyPI file's provenance.
- **CI covers each supported Ubuntu release explicitly.** `ubuntu-latest` had
  moved to 26.04, so 22.04 and 24.04 (what we run in production) were no
  longer tested. CI now pins 24.04 for the Python matrix and adds a
  `distro-smoke` job on 22.04, 24.04 and 26.04 using each release's own
  python3 in a venv.
- **harden on kernels without MPTCP** (e.g. WSL2, some custom kernels):
  `harden apply --mptcp-off` now says there is nothing to disable instead of
  reporting success, writes no drop-in, and reports a failed `sysctl -w`.
  `harden list` shows `n/a (not in this kernel)` rather than "unknown (run as
  root)" when already root; its JSON gains `mptcp_supported`.
- **"Public TCP listeners" ignores addresses on the loopback interface**
  (`127.0.0.53%lo`, WSL2's `10.255.255.254`), which are not reachable from
  outside.

## 0.12.10

Less noise in the KEV table, and numbers you can compare across hosts.

(There is no 0.12.9 release. The `v0.12.9` tag was pushed by mistake on a
commit that still carried version 0.12.8; release tags are protected and
cannot be moved, so the version was skipped. Nothing was published to PyPI
as 0.12.9.)

- **Laravel: one MEDIUM when laravel/framework is installed at more than one
  version** on a host, naming each path and version. Usually a stale vendor
  copy or a backup left under a web root; it was easy to miss across separate
  INFO rows. (#111)
- **Report: firewall drops show their time window.** The counters reset
  whenever the drop rules are recreated (every `kevward firewall apply`, and
  the boot-time reload), so a bare "since last ruleset load" made hosts hard
  to compare. The line now reads e.g. `since 2026-11-11 13:13 UTC, 9.0 h`:
  the later of the boot unit's start time and a stamp `firewall apply` writes
  to `/var/lib/kevward/firewall-counters-reset`. JSON gains
  `attackers.firewall_since` (epoch seconds or null).
- **KEV table: "n/a (release)" for rows Ubuntu's data rules out for this
  release.** A `possible` row becomes `na_release` only when Ubuntu marks an
  installed package `not-affected` on this release, or — kernel only — when
  this release is not tracked for the CVE, every tracked release is settled
  (released / not-affected / DNE) and the newest fix is on an older upstream
  kernel series than the one running (e.g. fixed in 4.4 while the host runs
  5.15). These rows move to a collapsed table with the reason; the summary
  shows the count separately, and JSON gains `na_release_count`. `applicable`
  and `fixed` are never changed. (closes #74)
- **Fix: `report --json` stdout is now pure JSON.** The `wrote <path>` line
  went to stdout before the JSON, so `kevward report --trends --json >
  posture.json` (as in the README) did not produce a valid JSON file. With
  `--json` it now goes to stderr; without `--json` nothing changes. (closes #113)
- **Internal: CI now runs the test suite (pytest)**, not only ruff and a
  smoke test. (#120, closes #112)

## 0.12.8

A broken config or a failed run can no longer go unnoticed.

- **Fix: a malformed `config.toml` no longer crashes kevward.** It used to
  make every command (including the scheduled report) exit with a traceback.
  Read-only commands now warn and run on defaults, and the report carries a
  HIGH finding; `apply --yes`, `firewall apply|flush --yes` and
  `schedule-reboot` refuse until the file is fixed. (#107, closes #104)
- **Report shows the config in use**: `config: /etc/kevward/config.toml`,
  `config: defaults`, or UNREADABLE in red; JSON gains `config_source` /
  `config_error`. (#107, closes #105)
- **Stale reports are detectable**: `<meta name="kevward-generated-at">`
  (+ version, host) in the HTML head, and `last-run.json` written next to the
  report on every run, including failures. README explains how collectors
  should flag a stale report. (#108, closes #106)

## 0.12.7

Fixes and KEV-table cleanups from the 2026-11-10 morning check.

- **Fix: `apply` installed minor upgrades without `--minor`.** Every pending
  package change was handed to `apply()`; the policy only decided whether a
  plugin applied at all. Security updates now follow `apply_security` and minor
  upgrades `apply_minor` (default: security only, as documented). (#97, closes #96)
- **`apply` lists and installs each package once.** A package owned by a
  service plugin and the host-wide `apt` plugin (e.g. apache2) appeared twice in
  the dry run. A dry run without root now notes that apt lists were not
  refreshed. (#101, closes #99)
- **KEV table: "n/a (config)" for CVEs this host's configuration rules out**,
  with the reason shown. First rules: OpenSSH "SSHole" (CVE-2026-123158;
  musl + PAM-disabled only, so n/a on glibc or `UsePAM yes`) and PHP-CGI
  CVE-2024-4577 (Windows-only). Fail-soft; never overrides `fixed`/`applicable`.
  (#98 closes #86, #100 part of #62)
- **`[trends] version_budget_s` / `max_version_checks`** make the
  version-aware KEV pass budget configurable (defaults unchanged: 45 s / 80), so
  hosts with many "not checked" rows can resolve them faster. (#102, part of #66)

## 0.12.6

- **CVE cache falls back to a per-user dir; warns when nothing is writable.**
  A non-root `trends`/`report` could not write `/var/cache/kevward/usn` and
  failed silently, so the same CVEs stayed "not checked" every run. It now uses
  `$XDG_CACHE_HOME`/`~/.cache` and still reads the root-written cache; if no
  cache is writable, the CLI and report say so. (#89, closes #65)
- **`[audit] allowed_forced_commands`**: glob patterns for expected
  authorized_keys forced commands (e.g. your report-collection key). Matching
  keys are no longer reported; others still are, now with the command shown. (#90)
- **Report shows when a newer kevward is on PyPI** (INFO finding with the
  upgrade command; looked up once a day, fail-soft, read-only). Opt out with
  `[update] check = false`. (#91, closes #70)

## 0.12.5

Fixes from the 2026-11-09 morning reports.

- **Fix: `composer audit` now audits the Laravel app, not kevward's cwd.** It
  ran without a working directory, so every project came back clean. It now
  passes `--working-dir`, and `--no-plugins --no-scripts` so a root run never
  executes code from a project's `vendor/`. (#82)
- **Laravel apps under `/home` are found.** The scan (depth-bounded, skipping
  hidden dirs, `vendor/`, `node_modules/`) now covers per-user checkouts; on two
  hosts this surfaced a second copy of an app on Laravel 11.9 / 11.11. Apps
  reached via overlapping roots are reported once. (#82)
- **Laravel end-of-security-support finding.** MEDIUM once a major's security
  fixes have ended (Laravel 11: 2026-03), LOW within 6 months of it. (#82)
- **Report: "reboot required" distinguishes now from later.** The header shows
  `YES` only when `/run/reboot-required` is set, and `after pending updates`
  when only a pending (e.g. kept-back) kernel would need one. JSON adds
  `reboot_pending`. (#83)
- **A kept-back kernel update is MEDIUM, not LOW**: `apt upgrade` never installs
  it, so it previously sat unnoticed. (#83)

## 0.12.4

Precision and clarity fixes from the 2026-11-08 morning reports.

- **KEV matching is now whole-word, with optional vendor pinning.** Host terms
  were matched as substrings, so `php` listed ThinkPHP, phpMyAdmin and PHPUnit
  CVEs, and the apache plugin's `http server` listed Oracle HTTP Server
  (CVE-2026-21962). Terms now match whole words in the KEV vendor/product, and
  `vendor:product` pins both (apache uses `apache:http server`). On a 22.04
  host this removed exactly those 5 false positives (51 -> 46 matches). (#80)
- **USN cache lasts 36h instead of 24h.** Daily reports run at the same time,
  so a 24h TTL expired the whole cache just before every run and the report hit
  its time budget, leaving CVEs `unchecked` (23 on one host). (#80)
- **Report: header counts say when they include audit indicators**, and an
  empty Findings table points to the audit section instead of saying
  "No findings." next to `low: 1`. (#80)
- **`firewall apply` skips IPs a permanent CIDR already blocks** and prunes
  such entries from the evidence set (they stay blocked by the CIDR), so
  `firewall list` shows what is actually new. `plan` reports
  `covered by permanent CIDR: N`; JSON adds `cidr_covered`. (#79)

## 0.12.3

- **Fix: the kevward firewall blocklist no longer disappears on reboot.**
  When saving the table for reboot-persistence, the `expires` cleanup also
  removed the comma after every element, so `/etc/kevward/firewall.nft`
  could not be loaded and `kevward-firewall.service` failed at boot with a
  syntax error. The table was missing until the next `firewall apply`. Seen on
  both Ubuntu 24.04 hosts after a kernel reboot; every host that had saved a
  multi-element blocklist was affected on its next reboot. The saved file is
  now validated with `nft -c` before the boot unit is enabled. (#77)
- `kevward firewall list` now says when kevward's table is not loaded (and
  points at the boot unit if it is enabled) and exits 1, instead of printing
  only the unit state.
- The HTML report shows a red "kevward firewall not loaded" warning in Attack
  sources when the boot unit is enabled but the table is absent.

After upgrading, run `sudo kevward firewall apply --yes` once on each host to
re-create a missing table and rewrite a valid saved ruleset.

## 0.12.2

Fixes found by the first automated morning summary.

- **Fix: the report no longer cuts the KEV table off silently.** It listed only
  the first 30 matches with no indication (51 matches on the 22.04 hosts, so 21
  were never shown). The HTML report now lists every match; the `trends` CLI
  still prints 25 but ends with `... and N more`. (#72)
- **Fix: kernel updates kept back by `apt-get upgrade` are now reported.**
  The apt check simulated `apt-get upgrade`, which never installs new
  packages, so a kernel update (`linux-generic` / `linux-image-generic` pulling
  in a new `linux-image-*`) was silently "kept back" and never became a
  finding — including when it came from `-security`. Seen on both Ubuntu 24.04
  hosts: `linux-libc-dev` 6.8.0-149 was reported while the running kernel
  stayed at 147. kevward now also simulates `dist-upgrade` and reports the
  difference as `… (kept back)` findings with the usual security severity, a
  reboot flag for kernel metapackages, and the command to apply them. Parsing
  stays locale-independent (only `Inst` lines are read). (#73)
## 0.12.1

Follow-up fix to 0.12.0's `unchecked` status.

- **Fix: CVEs Ubuntu does not track no longer stay `unchecked` forever.**
  ubuntu.com answers 404 for KEV entries outside its tracker (Composer/npm
  products such as Livewire, PHPUnit, ThinkPHP, systeminformation, or upstream
  versions Ubuntu never shipped). 0.12.0 treated that like a network failure:
  the CVE was reported `unchecked`, never cached, and re-fetched every run,
  eating the time budget. A 404 is now cached as "not tracked by Ubuntu" and
  labelled `possible`; 5xx and transport errors remain `unchecked`. Seen on
  tk2-225, where 7 such CVEs never converged. (follow-up to #61)

## 0.12.0

Accuracy fixes from a daily check across four hosts: sshd hardening gaps,
an honest period for sshd-failure totals, and KEV version checks that no
longer hide an incomplete run.

- **Fix: KEV version check no longer hides an incomplete run as "possible".**
  Two hosts on the same kernel (5.15.0-202) disagreed on CVE-2025-38352
  (fixed vs possible): when a lookup failed or the per-run time budget/cap ran
  out, every remaining CVE was silently labelled `possible`, indistinguishable
  from "looked up, nothing installed to judge". These are now a separate
  **`unchecked`** status (amber pill, counted as "N not checked" in the report
  and CLI; JSON `unchecked_count`). The pass also converges instead of
  depending on network speed: fresh-cached CVEs are classified first, each
  fetch's timeout is capped by the remaining budget, and after the budget is
  spent remaining CVEs fall back to any cached entry, however old, before being
  reported unchecked. (#61)
- **`report`: say what period the sshd failure totals cover.** The totals are
  summed over every rotated `auth.log*`, so a large historical number (e.g.
  477,768 from a subnet already blocked) read as a live attack. The Attack
  sources section now shows the covered date span and a second line with the
  last-24h attempts/sources and last-7d attempts. Both classic syslog and
  RFC 3339 auth.log stamps are parsed (year rollover handled). JSON gains
  `ssh_window_start`, `ssh_window_end`, `ssh_attempts_24h`, `ssh_attempts_7d`,
  `ssh_sources_24h`; existing keys are unchanged. (#58)
- **sshd: flag `LoginGraceTime 0` (MEDIUM).** Unauthenticated connections are
  then never timed out, so an attacker can hold pre-auth slots open and exhaust
  `MaxStartups`, locking administrators out. This is typically a leftover of the
  2024 regreSSHion (CVE-2024-6387) stop-gap and was found on a production host.
  The detail names the current `MaxStartups`. (#59)
- **Fix: sshd now catches `PermitRootLogin without-password`.** Ubuntu 22.04's
  `sshd -T` prints the legacy spelling, which the check did not recognise, so
  key-only root login went unreported there. Both spellings are now flagged —
  at **LOW** (was MEDIUM for `prohibit-password`): password root login stays
  HIGH, key-only root login is a hardening nudge. The checks moved into a pure,
  unit-tested `classify_sshd_config`. (#59)

## 0.11.0

Operational polish from a week of daily runs: quieter and more accurate EOL
reporting, an `apply` that says why it failed, and the firewall's own drop
counts surfaced in the report.

- **`report`: show the kevward version in the output.** The HTML report's header
  and footer now carry `kevward X.Y.Z`, and the JSON (`report --json`,
  `trends --json`) gains a `kevward_version` field — so a report says which
  version produced it (useful for triage and confirming an upgrade took
  effect). Read from `kevward.__version__`; presentational only. (#50)
- **Fix: EOL checks no longer flag versions with years of support left.** The
  PHP and Node.js runtime EOL checks flagged *any* known version, so PHP 8.4
  (supported to 2028-12) was reported as "nearing/after end of security
  support" in 2026. A new shared, unit-tested `plugins/_eol.eol_phase` compares
  the support-end month to today and emits a finding only when support has
  ended (MEDIUM, "past …") or ends within ~6 months (LOW, "nearing …");
  otherwise nothing. (#53)
- **`apply`: say why an apt step failed, and exit non-zero.** Running
  `apply --yes` without root printed a bare `[apt] FAIL: install: …` with no
  reason. The failure reason is now shown inline
  (`requires root -- re-run with sudo`), and `apply` returns a non-zero exit
  code when any step fails, so automation can tell a no-op from a failure.
  Read-only commands still run fine as non-root. (#54)
- **`report`: show firewall drop counters (follow-up to #42).** The Attack
  sources section now reports how many packets kevward's nftables sets dropped
  — evidence blocklist vs operator CIDR blocks, plus a total — framed "since
  last ruleset load" (the counters reset on each reload). A pure, unit-tested
  `firewall.parse_drop_counters` reads them from an `nft list table` dump;
  read-only, and the line is omitted when the table or counters are absent.
  (#55)

## 0.10.0

Compromise detection, second wave: four more read-only `audit` checks for the
footholds a post-intrusion attacker leaves behind — rogue accounts, setuid
backdoors, shell-rc credential hijacks, and more persistence spots.

- **`audit`: four new compromise checks (deeper foothold detection).** All
  read-only, stdlib-only, *possible* not *confirmed*, with unit-tested pure
  classifiers:
  - **Rogue local accounts** — a UID-0 account other than `root`, a login
    account with an empty password, a `NOPASSWD: ALL` sudoers grant, or a
    world-writable sudoers file. (#37)
  - **SUID/SGID anomalies** — a setuid/setgid shell or interpreter, or a
    setuid/setgid file in a temp or hidden path (a classic root backdoor the
    patch/port view misses), over a bounded directory walk. (#29)
  - **Shell-rc credential hijacks** — a function or redirecting alias wrapping
    `sudo`/`ssh`/`su`/`passwd`, or `PROMPT_COMMAND`/`BASH_ENV` wired to run a
    command; benign convenience aliases are not flagged. (#32)
  - **Extended persistence** — `at` jobs and user-level systemd `.service`
    units are now scanned alongside cron and system units (a malicious timer's
    payload is its paired service, caught with the units). (#39)
- **Fix: false "reboot required" on `linux-firmware` / `libc*` package updates.**
  The reboot flag used `pkg.startswith(("linux-", "libc"))`, which wrongly fired
  on firmware blobs (`linux-firmware-*`), kernel headers/tools, and every
  `libc`-prefixed library (`libcurl`, `libcups`, …). It is now narrowed to the
  kernel image (`linux-image*`) and glibc (`libc6`) via a new
  `util.pkg_needs_reboot`, so a routine firmware upgrade no longer reports the
  host as needing a reboot.

## 0.9.0

Sharper signal: a KEV match now tells you whether it actually applies to *this*
host's installed versions, and a permanent firewall block shows how much it is
really catching.

- **`trends`: version-level KEV applicability.** A name-matched CISA KEV CVE is
  now cross-referenced against this host's installed source-package versions
  using Ubuntu's per-CVE security data, so each match is labelled **applicable**
  (affected and not yet patched here), **fixed** (already at/after the fix), or
  **possible** (couldn't confirm the version). Per-CVE, cached under
  `/var/cache/kevward`, bounded by a count cap and a wall-clock budget, and
  fully fail-soft: offline or without data it falls back to the existing
  name-level "possible" labelling (no regression). stdlib-only; Debian version
  comparison is implemented in-tree (prefers `dpkg` at runtime). Shown in
  `kevward trends` and the `--trends` report. (#3)
- **`firewall`: packet counters on the block rules.** The `drop` rules for the
  evidence and permanent-CIDR block sets now carry an nftables `counter`, so
  `kevward firewall list` / `nft list table inet kevward` shows how many
  packets each block set has actually dropped — a direct, read-only answer to
  "is this block still catching traffic?" that the cumulative sshd log can't
  give. Counters are reasserted on `firewall apply`; existing hosts pick them
  up on their next apply.

## 0.8.0

Compromise detection, deeper: three new read-only `audit` checks aimed at the
footholds real post-intrusion campaigns leave behind.

- **`audit`: package integrity via `dpkg --verify`.** Flags installed files
  whose checksum no longer matches the package — a modified / backdoored system
  binary (e.g. a trojanised `sshd` / `sudo` / `curl`) — with no stored baseline
  for an attacker to tamper with. Known post-install churn (CA bundles, bundled
  pip wheels) is suppressed to stay low-noise; non-Debian hosts are skipped. (#34)
- **`audit`: rogue process origin.** Flags a process backed by a deleted,
  temp-resident (`/dev/shm`, `/tmp`) or hidden executable — an in-memory implant
  — or one wearing a kernel-thread name (`[kcached]`-style) while backed by a
  real binary. A plain deleted exe at a normal path (a daemon pending restart
  after an upgrade) is deliberately ignored. (#28)
- **`audit`: PHP `auto_prepend_file` / `auto_append_file` hijack.** Flags a PHP
  prepend/append directive pointed at a temp, hidden, or world-writable file —
  a stealthy web-server foothold that runs on every request. (#30)

## 0.7.0

One page, the whole picture: the daily report can now also say whether the host
looks compromised, not just how exposed it is.

- **`kevward report --audit` folds compromise indicators into the HTML report.**
  The daily report can now include the `kevward audit` findings (reverse SSH,
  backdoor sockets, persistence) as their own "Host compromise indicators"
  section, and their severities count toward the report's header totals — so one
  page shows patch posture, attacker IPs *and* whether anything looks like a
  foothold. Off unless `--audit` is passed (audit reads processes/sockets/files
  and wants root for full visibility); the rest of the report is unchanged.

## 0.6.0

Detection past the perimeter: a read-only scan for a foothold *after* an
attacker is in, complementing the patch/exposure posture kevward already covers.

- **`kevward audit` — read-only host compromise indicators (local host only).**
  A new subcommand that looks for the signs of a post-intrusion foothold, past
  "who is knocking": **reverse SSH / tunnels** (`ssh`/`autossh` with `-R`/`-D`),
  **reverse shells & bind backdoors** (an established outbound socket to an
  external host owned by a shell/interpreter, or a shell listening on a
  non-loopback address — inbound to your own services is ignored), and
  **persistence** (`/etc/ld.so.preload`, cron, admin-added systemd units, shell
  rc / `profile.d`, and `authorized_keys` carrying reverse-shell/downloader
  patterns, forced commands, or world-writable permissions). `kevward audit`
  prints findings (`--json` for machine output). It is strictly read-only — it
  never kills a process, deletes a file, or touches a remote host; findings say
  *possible*, not *confirmed*. Run with `sudo` for full visibility. (#7)

## 0.5.1

- **Fix: `kevward firewall` no longer allowlists a transient `:22` peer.** The
  persisted nftables *accept* set was built from `ss`-listed established SSH
  connections, which can include an attacker mid-brute-force — persisting that
  IP as "allowed" defeated the blocklist for it. The accept set now contains
  only stable entries (the allowlist floor, configured `allow`, and the running
  session's own SSH source); the broader established-peer scan is still used for
  the in-memory self-block guard, where it is recomputed each run and never
  persisted. Re-run `firewall apply` to regenerate a clean accept set. (#17)

## 0.5.0

Firewall hardening: known-bad networks can be blocked permanently, and the
active-defense blocklist now survives a reboot.

- **`kevward firewall` permanent block list (`block`), CIDR-capable.** A new
  `[firewall] block` (and `--block`) is the mirror of `allow`: operator-declared
  permanent blocks, given as a CIDR or a single IP, with no TTL. The allowlist
  still **always wins** — it is now an nftables *accept* set checked before the
  drops, so a bad `block` entry can't lock out loopback, RFC1918, a configured
  `allow`, or the live admin/SSH source. Permanent blocks live in their own
  `interval, auto-merge` sets so overlapping ranges merge instead of erroring;
  evidence-based entries keep their TTL as before. An older-schema table is
  recreated once on the next `apply`. (#13)
- **`kevward firewall` reboot-persistence.** `apply` now installs a kevward-owned
  `kevward-firewall.service` that re-applies the saved blocklist on boot (mirrors
  `kevward-harden`), so the active-defense set survives a reboot instead of
  needing a manual re-`apply`. `--no-persist` (or `[firewall] persist = false`)
  opts out; `flush` removes the unit and the saved ruleset too. (#12)

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
