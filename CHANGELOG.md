# Changelog

## Unreleased

- **truthgate: no `.pyc` written into the package at run time (#228).**
  kevward sets `sys.dont_write_bytecode`; `self.update` byte-compiles the
  new package itself, inside the update, so nothing in the package directory
  changes outside a maintenance window.
- **truthgate: `plan` reports `apply_timeout_s` (#220)**, an upper bound for
  the apply job (300 s overhead + `[apt] install_timeout_s` per install run;
  `null` when `install_timeout_s = 0`), to size the maintenance window.

## 0.20.2

kevward's firewall survives an uninstall/reinstall and a missing firewall is
reported (#243, #244); report units from the old example no longer hide
/home and /tmp from the audit (#246); #245. Updating with `self.update` is
enough: the managed drop-in and the firewall record are written on the way.

- **Fix: a reinstalled host lost kevward's firewall (#243).** `firewall
  apply` records `/var/lib/kevward/firewall.json` (kept by `uninstall` unless
  `--purge`; written by `setup --refresh` for hosts that applied it before).
  The uninstall snapshot includes it, `setup --restore` re-applies the
  blocklist with the console's addresses allowed, and plain `setup` reports
  it as not loaded.
- **Fix: no "firewall not loaded" warning once the boot unit was gone (#244).**
  Table missing while the blocklist is in use is now a HIGH finding with the
  red line, and the drops line is always shown.
- **Fix: report units from the old example hid /home and /tmp (#246).** The
  managed drop-in sets `ProtectHome=no` / `PrivateTmp=no`; the report warns
  when it runs sandboxed; the ssh-gate key check no longer says "missing"
  when it could not look; `systemd/kevward-report.service` matches `schedule
  install`; `schedule status` warns.
- The previous-report comparison sits next to the 24 h sshd figure (#245).

## 0.20.1

The report is rebuilt after a console apply and on request (`report.refresh`),
and report.json records the last apply (#240).

- **The report is rebuilt after an apply (#240).** report.html is now written
  via a temporary file and rename, like report.json. An apply job that
  installed something restarts the daily report unit at its end
  (`result.report_refresh`), so the console shows the result right away.
  ssh-gate `report.refresh` (operate) does the same on request
  (`previous_generated_at`, `running`, a minimum interval), and
  `report.json` has `last_apply` (job, finished, state, installed count).

## 0.20.0

No manual steps on the host after an update or a reinstall: `self.update`
refreshes kevward's unit drop-ins (#235), `uninstall` saves a snapshot that
`setup --restore` puts back (#236), and the report warns when the console
cannot get in (#237). Also #234.

- **No more manual steps after an update (#235).** `self.update` runs the new
  version's `kevward setup --refresh`, which rewrites kevward's managed unit
  drop-ins (the report service's `ReadWritePaths`, #227) and reloads systemd.
  `kevward schedule install` (and ssh-gate `schedule.install`, and `setup
  --timer`) now keep the recorded time instead of resetting it to 07:00.
- **Uninstall and reinstall without hand work (#236).** `kevward uninstall`
  saves `/var/lib/kevward/setup-snapshot.json` (public keys, timer time,
  fail2ban exemption) before removing anything; `kevward setup --restore`
  puts it all back.
- **The report warns when the console cannot get in (#237):** ssh-gate
  enabled but no authorized_keys entry uses it, or operate keys without
  `/etc/sudoers.d/kevward-ssh-gate`.
- **Fix: uninstall rejected kevward's own timed block-list elements (#234)**
  when nft printed several on one line.

## 0.19.3

The report timer's `apt-get update` works under the read-only service: a
writable TMPDIR for apt's signature checks (#231). No extra step after
updating if `kevward schedule install` already ran with 0.19.2.

- **Fix: the report timer's `apt-get update` failed signature checks (#231).**
  `ProtectSystem=strict` also keeps /tmp read-only, where apt writes a
  temporary config for apt-key/gpgv ("Couldn't create temporary file
  /tmp/apt.conf…"), so the old index files were kept. kevward now runs it
  with `TMPDIR=/var/cache/kevward/tmp` (owned by apt's sandbox user `_apt`);
  /tmp stays read-only. `lists_updated_at` is the time of kevward's own
  successful refresh (the `*Release` files carry the repository's
  Last-Modified time), and the recorded error prefers an `E:` line.

## 0.19.2

The report timer can refresh the apt lists again (#227); stale or failed
lists are now reported (#179). **After updating, run `sudo kevward schedule
install` (or ssh-gate `schedule.install`) once on each host.** Also:
allowed_forced_commands match counts (#224) and sshd failures compared with
the previous report (#225).

- **Fix: the report timer could not refresh the apt lists or write kevward's
  state (#227).** The service runs with `ProtectSystem=strict` and only
  `/var/log/kevward` and `/var/cache/kevward` were writable, so `apt-get
  update` failed ("Read-only file system") in every timer run and the lists
  were only as fresh as Ubuntu's own apt-daily timer; the NEW forced-command
  state (#215) was never saved either. `kevward schedule install` now writes
  a managed drop-in (`kevward-report.service.d/50-kevward-paths.conf`) adding
  `/var/lib/kevward`, `/var/lib/apt/lists` and `/var/cache/apt`, and
  `schedule status` warns when they are missing. **Run `sudo kevward schedule
  install` (or ssh-gate `schedule.install`) once on existing hosts.**
- **report: a failed `apt-get update` or stale package lists are a MEDIUM
  apt finding (#179),** with a hint when a repository changed its Release
  Label/Origin (kevward never accepts that itself). The header shows when the
  lists were last updated; `apt_refresh.lists_updated_at` in the JSON.
- **audit: whether `[audit] allowed_forced_commands` matched (#224).** A line
  under the audit table per pattern, the loaded patterns on forced-command
  findings that are still reported, and `audit_allowed_forced` in the JSON.
- **report: sshd failures compared with the previous report (#225).** The
  last-24h line shows the previous value and the change; report.json has
  `summary.attack.previous` and `ssh_failed_24h_change_pct`; an INFO finding
  when failures at least double (and rise by 50 or more).

## 0.19.1

From the 2026-11-23 morning check: the ssh-gate change log records the
console's address again (#214), forced-command keys added since the previous
report are NEW (#215), and report rows carry untranslated data-* keys (#216).

- **Fix: changes made through ssh-gate were logged "from unknown" (#214).**
  sudo drops `SSH_CONNECTION` for the operate role. `kevward setup` now keeps
  it (`Defaults!… env_keep += "SSH_CONNECTION"` in the sudoers drop-in), and
  hosts without that line get the address from the sshd session's process.
  When neither works the log says why instead of "unknown".
- **audit: forced-command keys added since the previous report are NEW
  (#215).** Reported separately at medium for two days; the ones that are
  always there stay one low finding.
- **report: rows carry the untranslated keys (#216)** as `data-severity`,
  `data-service` and `data-kind`, so scripts do not depend on the display
  language (report.json remains the way to read the data).

## 0.19.0

The report as data for consoles: `report.json` with a `summary` (counts, KEV,
attack telemetry), ssh-gate `report.get` `format: "data"`, and count meta tags
in report.html (#211).

- **`report.json` (#211).** `kevward report` also writes the run as data
  beside report.html: the `report --json` object plus `schema_version: 1` and
  a `summary` computed exactly as the HTML header (`counts` per severity,
  `act_now`, `kev` with the applicable CVEs, `attack` with fail2ban / sshd
  totals, their window and firewall drops). ssh-gate `report.get` takes
  `format: "data"` to return it.
- report.html carries the header counts as `kevward-count-*` meta tags, and
  `last-run.json` has the same `counts`.

## 0.18.2

ssh-gate `job.get` now works with the read role (#208).

- **Fix: ssh-gate `job.get` with the read role said `not_found` (#208).**
  `/var/lib/kevward/jobs/` was root-only. The directory is now `0755` and job
  files and logs `0644` (a `0750` directory from 0.18.0/0.18.1 is corrected
  on the next job). A job that exists but cannot be read is `forbidden`, not
  `not_found`.

## 0.18.1

Fixes for problems found with 0.18.0 and FR Security Centre: `reboot.*` failed
on hosts with nothing scheduled (#203), and `setup --fail2ban-ignore` wrote a
drop-in that stops fail2ban at its next start (#204). Hosts that ran it should
check `sudo fail2ban-client -t` (re-running setup rewrites the drop-in). Also
`setup --self-update` / `--allow-reboot` (#205).

- **Fix: `reboot.status` (and `reboot.schedule` / `reboot.cancel`) failed with
  `ValueError` when nothing was scheduled (#203).** logind reports "no schedule"
  as `USEC_INFINITY` (2^64−1) as well as 0; both now mean none, as does any
  out-of-range time. `scheduled_reboot()` never raises: anything unexpected is
  `{"state": "unknown"}`. ssh-gate `internal` errors now carry the first line
  of the message, not only the exception type.
- **Fix: `kevward setup --fail2ban-ignore` wrote a drop-in that stops fail2ban
  at its next start (#204).** `%(known/ignoreip)s` does not work in `[DEFAULT]`.
  The drop-in now lists fail2ban's default, the `ignoreip` already in effect,
  and the new addresses. It is checked with `fail2ban-client -t` and removed
  or restored if rejected; reload only runs after the check passes.
- **`kevward setup`: the `authorized_keys` lines are written last**, and a
  failure reports which steps were already applied (and logs them).
- **`kevward setup --self-update` / `--allow-reboot` (#205).** Set
  `[ssh_gate] self_update = true` / `[policy] allow_reboot = true` in the same
  validated, backed-up write as `--ssh-gate`.

## 0.18.0

ssh-gate phase 2 for consoles such as FR Security Centre: reviewed updates
(`plan` → `apply.start` → `job.get`, #197), reboot scheduling (#198) and the
report timer (#199). The host's policy still decides what may be applied and
whether it may reboot.

- **ssh-gate: reboots (#198).** `reboot.status` (read) shows the scheduled
  reboot, who set it, and whether one is required. `reboot.schedule` (operate)
  schedules one with the host's `shutdown -r`, only with `[policy]
  allow_reboot = true`, 5 minutes to 7 days ahead, and `conflict` on an
  existing schedule unless `replace`. `reboot.cancel` (operate) runs
  `shutdown -c`.
- **ssh-gate: report timer (#199).** `schedule.status` (read) and
  `schedule.install` (operate) expose `kevward schedule status` / `install`.
- **ssh-gate: plan / apply.start / job.get (#197).** `plan` returns the
  dry-run plan with a `plan_hash`. `apply.start` re-plans as root, refuses
  with `conflict` if the hash changed, and runs `kevward apply --yes
  --expect-plan <hash> --job <id>` in a transient systemd unit, optionally
  scheduling a reboot afterwards if one is needed. `job.get` returns the job's
  state, result and log tail. Apply policy stays host-only.
- **`kevward apply --expect-plan <sha256>`.** Installs only if the plan still
  has that hash, from the same apt simulation that was hashed.
- Each gate reboot/timer/apply change is logged to syslog and the change log, and the
  report shows it as an INFO finding for 7 days.

## 0.17.0

Host lifecycle for consoles such as FR Security Centre. ssh-gate `self.update`
updates or rolls back kevward (#190). `kevward setup` writes the gate keys,
sudoers, timer and fail2ban ignore in one command (#191). `kevward uninstall`
removes kevward cleanly without locking out SSH (#192). `self.update` is
available from this release, so the update to 0.17.0 itself is done by hand.

- **`kevward uninstall` (#192).** Removes kevward cleanly. Without `--yes` it
  is a dry run, and `--json` prints the ssh-gate envelope.
  - It removes the systemd units (report, firewall, harden), the ssh-gate
    sudoers file, ssh-gate lines in authorized_keys, setup's fail2ban
    drop-in, the harden sysctl drop-in, the nft tables and their boot
    persistence, the launcher, and finally `/opt/kevward`.
  - Config, reports and state stay unless `--purge`. Collector keys are
    removed only with `--remove-collector-keys`.
  - The firewall is checked first. If a kevward table contains anything
    kevward did not write (any rule other than its own set drops/accepts, a
    `policy drop`, a jump), or `/etc/nftables.conf` mentions kevward, it
    returns `conflict` and changes nothing.
  - Persistence is removed before the tables, so no rule comes back after a
    reboot (the 2026-11-08 class of accident).
  - It is logged to syslog and the change log.
- **`kevward setup` (#191).** One root command that makes a host console-ready.
  It replaces the authorized_keys line that was pasted by hand, which went wrong
  on 2026-11-22 and got the operator banned by fail2ban.
  - `--read-key` / `--operate-key` (with `--console-user`) write the
    ssh-gate lines:
    - Each key is validated. An existing line for the same key, or an older
      gate line with the same comment, is replaced instead of duplicated.
    - A symlinked or group/world-writable `.ssh` or `authorized_keys` is
      refused, and the file is written atomically.
  - `--operate-key` also writes the exact-match sudoers file, checked with
    `visudo -cf` and installed 0440.
  - `--ssh-gate` enables the gate in config.toml. The config is validated
    (#186) and backed up first.
  - `--timer` installs the daily report timer.
  - `--fail2ban-ignore` adds an `ignoreip` drop-in that keeps earlier
    settings.
  - `--refresh` is reserved for the post-update steps of self.update.
  - Running it twice changes nothing. `--dry-run` lists the changes,
    `--json` prints the ssh-gate envelope, and every change is logged and
    shown in the report for 7 days. It never enables the firewall.
- **ssh-gate `self.update` (#190).** A console can now update kevward on a host,
  or roll it back, with `{"op":"self.update","args":{"version":"X.Y.Z"}}`
  (operate role).
  - Only a validated `X.Y.Z` is accepted. The package name is fixed.
  - pip runs as `--isolated` with a clean environment and PyPI as the only
    index, under a lock and a 300 s limit. Afterwards the new
    `kevward --version` is checked.
  - It is refused unless kevward runs from the `/opt/kevward` venv, the host
    opts in with `[ssh_gate] self_update = true`, and the version is at or
    above `[ssh_gate] min_version` (default: the first release with the op).
  - The response carries `old`, `new`, `downgrade`, `duration_s` and
    `pip_tail`. An unknown version returns `not_found`, and a concurrent run
    returns `conflict`.
  - Each update is logged and shown in the report for 7 days.
  - The `version` op now reports `install`, `self_update` and `min_version`.
  - `util.run` gained `clean_env`.

## 0.16.0

`kevward ssh-gate`, a restricted forced command for collection and console
SSH keys (#185), and config validation that reports settings kevward would
otherwise silently ignore (#186).

- **`kevward ssh-gate` (#185).** A forced command for collection and console
  SSH keys, using the same one-request JSON envelope as stille-pro
  `dispatch`.
  - It is off unless `[ssh_gate] enabled = true`.
  - The `read` role (no sudo) offers `version`, `report.get` (HTML or JSON),
    `config.get` and `config.schema` (every key, type, default, help text and
    whether it is writable).
  - The `operate` role (`sudo -n`, exact-match sudoers) adds `config.set`.
  - `config.set` only writes an allowlist of keys that cannot weaken
    detection or protection and are not paths.
  - It refuses a write if the file changed since `config.get` (`conflict`),
    or if kevward's own loader or the #186 validation rejects the result.
  - It keeps the last 10 backups, replaces the file atomically, and logs each
    change to syslog and `/var/lib/kevward/ssh-gate-changes.jsonl`.
  - The report shows each change for 7 days.
  - `audit` recognises the gate's own forced commands.

- **Config: ignored settings are reported (#186).** On 2026-11-22
  `allowed_outbound` written below a new `[report]` table became
  `report.allowed_outbound` and was dropped without a word, so expected tor
  connections were listed as "unexpected outbound". Unknown tables, unknown
  keys and known keys in the wrong table now produce a warning ("unknown
  setting `allowed_outbound` in [report]; ignored — did you mean [audit]?") on
  stderr for every command, a MEDIUM finding and a note on the config line in
  the report, and `config_warnings` in the JSON. Loading still continues. The
  audit section shows how many `allowed_outbound` / `allowed_forced_commands`
  rules were loaded (`audit_rules` in the JSON).

## 0.15.0

The HTML report can now be read in Japanese, and its layout follows the
stille-hunter weekly report: logo, a one-line summary of what needs action,
and colour-coded categories (#180). Set `[report] lang = "ja"` in
config.toml, or pass `kevward report --lang ja`; English stays the default.

- **Report layout aligned with the stille-hunter weekly report (#180).** The
  kevward logo (inlined, inverted in dark mode) sits top-left; a summary card
  says in one line whether anything critical/high or an applicable KEV needs
  action, with a matching "to act on" chip; cards are grouped under coloured
  category headers (this host — mustard, attacks on this host — magenta, signs of
  intrusion — red); tables scroll inside their card on narrow screens, and
  labels and table headers no longer wrap mid-word.
- **Japanese report (#180).** `[report] lang = "ja"` in config.toml, or
  `kevward report --lang ja` for one run, renders the HTML report's frame in
  Japanese: headings, explanations, table headers, severity / kind / KEV
  status labels, the header line, firewall / fail2ban / sshd summaries, the
  audit intro and helper lines such as "still old" and "advisories". Finding
  titles and details from plugins, JSON and CLI output stay English (phase
  2). English remains the default. No new dependency: an in-tree catalog keyed by the English
  text, with a test that every message has a Japanese entry. An unknown
  `lang` is a config error.

## 0.14.3

Clearer `apply` and report output from the week's patching: whether the apt
plan is current and why a reboot is mentioned (#171), which packages of an
apt finding are still old (#174), and the `allowed_outbound` line at 0 hits
(#175).

- **`apply` says what happened (#171).** The dry run on www printed only
  `DRY RUN`, blank lines and `reboot required (not scheduled; …)`. Now:
  - the first line says whether apt lists were refreshed
    (`apt lists refreshed (apt-get update ok, 3.2s)`); a failed
    `apt-get update` was silently ignored and now prints `WARNING: apt-get
    update failed (…); the plan below may be stale` and exits 1;
  - `nothing to apply (0 packages)` when there is nothing to do, and
    `N minor upgrades not included (use --minor)`;
  - the reboot line says why: `already required (libc6)`, `will be required
    after these updates (linux-generic)`, or `will be required once pending
    updates not in this plan are installed`; nothing when neither applies.
  The apt plan (and `apt-get update`) is now computed once per run and
  shared by every apt plugin instead of once per plugin. JSON adds
  `apt_refresh`.
- **Laravel: one EOL finding per major (#171).** Two copies of the same app
  gave two identical MEDIUM "past end of security fixes" rows; they are now
  one row listing the paths.
- **Report: which packages of an apt finding are still old (#174).** A
  finding such as `php8.3 8.3.36 → 8.3.37` did not say whether it meant the
  whole php8.3 source or only the `php8.3` metapackage (left behind by
  `apt-get install --only-upgrade 'php8.3-*'`). The HTML row now lists
  `still old: <package> <installed version>` and how many other installed
  packages of the same source are already at the new version. JSON adds
  `source_package`, `package_versions` and `updated_packages` to apt
  findings (one extra `dpkg-query -W` per run).
- **audit: the `allowed_outbound` summary stays when nothing matched
  (#175).** With rules configured but no matching connection at scan time,
  the line disappeared, so "tor was not connected right now" looked the same
  as "the rule is not configured". Now `allowed outbound: 0 (rules:
  tor:9001; no matching connection at scan time)`, and
  `audit_allowed_outbound` in JSON lists every rule, at 0 when idle.

## 0.14.2

Two `apply` bugs found while patching the 2026-11-19 PHP release: PPA PHP
security releases were skipped, and a long kernel install could be killed
half-way.

- **PHP security releases from the ondrej/php PPA are security updates
  (#169).** Only origins with "security" in their name (Ubuntu's -security
  pockets) counted, so PHP 8.2.36 / 8.3.37 / 8.4.28 (2026-11-19, seven
  critical CVEs) showed as `low · minor_upgrade` on hosts using the PPA and
  `kevward apply` skipped them. A pending PHP upgrade from a non-security
  origin is now checked against php.net's release data (one request per PHP
  branch, cached 12h): a security release in between makes it a HIGH
  `security_update` linking the PHP announcement; if php.net cannot be
  reached it stays `low` and says "security status unchecked". New `[apt]`
  section: `php_release_check` (default true) and `security_origins`
  (globs on the origin name, default empty). apt findings carry their
  `origin` in the JSON output.
- **`apply` no longer kills a long apt-get after 600 s (#170).** A kernel
  install can take minutes on a small VPS, and killing apt-get in the middle
  can leave dpkg half-configured. The limit is now `[apt] install_timeout_s`
  (default 3600, 0 = none); apt-get output is shown as it runs; apt-get runs
  non-interactively (`DEBIAN_FRONTEND=noninteractive`, keep local conffiles,
  like unattended-upgrades) so it can no longer wait on an invisible prompt.
  On failure or timeout kevward runs `dpkg --audit` and says whether
  `sudo dpkg --configure -a` is needed, and not to reboot until it is clean
  when a kernel was involved.

## 0.14.1

- **audit: password logins from before password auth was turned off are no
  longer HIGH (#165).** The #87 check compared old auth-log lines with
  today's sshd setting, so a host's initial-setup logins (www2, 2026-10-25,
  15 minutes before `PasswordAuthentication no` was written) showed as a
  possible bypass. Logins older than the earliest sshd config file with an
  active `PasswordAuthentication no` are now INFO, naming that file and its
  change time; later ones stay HIGH, and locked-account logins are never
  excused.

## 0.14.0

Runs without me: releases tag and publish themselves, the report timer and
scheduled reboots are managed and visible from kevward, and several checks
that silently said "fine" now report what they could not check. Plus new
audit signals (impossible password logins, expected-outbound allowlist) and
which PHP-FPM is really serving the site.

- **Which PHP-FPM is actually served (#85).** nginx now reports one INFO
  listing what each server block serves (`hokaku.example.jp -> root
  /var/www/.../public; PHP 8.3 FPM`), parsed from `nginx -T` (which follows
  the sites-enabled symlinks `grep -r` missed). The php plugin checks every
  running `phpX.Y-fpm`, not just the CLI: an end-of-life branch is MEDIUM
  (near: LOW) with its package origin (Ubuntu archive or a PPA such as
  ondrej/php); running FPMs no nginx/Apache config references are listed as
  INFO; and an in-use FPM that `apt autoremove` would remove is MEDIUM, with
  the `apt-mark manual` command. Read-only; without root (no `nginx -T`) the
  unused/autoremove checks are skipped rather than guessed. PHP 8.5 added to
  the EOL table.
- **`kevward schedule` manages the daily report timer (#69).** `install
  [--at 07:00] [--jitter 20min] --yes` writes the service and timer only if
  missing and puts the schedule in a `50-kevward.conf` drop-in
  (`RandomizedDelaySec`, `FixedRandomDelay=yes`), then enables and restarts
  the timer; without `--yes` it is a dry run. `status` shows the effective
  schedule, delay and next/last run and warns about a timer with no random
  delay. `uninstall --yes` removes only what `install` created. Hand-edited
  units and other drop-ins are never overwritten or removed.
- **audit: password logins that should be impossible (#87).** A `sshd ...
  Accepted password for <user>` in the auth logs is HIGH when sshd has
  `PasswordAuthentication no` or the account's password is locked (`!`/`*` in
  /etc/shadow; hashes are never read out). `keyboard-interactive/pam` is
  flagged only for locked accounts (PAM may run OTP). This is the shape of
  auth-bypass bugs like SSHole (CVE-2026-123158). One finding per user and
  source IP, with the count and the last log line.
- **Release tags are created automatically (#88).** Merging a
  `release/X.Y.Z` pull request runs `release-tag.yml`: it checks that the
  branch name, `pyproject.toml`, `kevward/__init__.py` and a `## X.Y.Z`
  CHANGELOG section agree, tags the merge commit `vX.Y.Z` (never an existing
  tag) and starts `publish.yml` on it. Tagging by hand still works.
- **See whether a reboot is scheduled (#114).** The report header shows
  `reboot scheduled: 2026-11-13 21:00 JST` (or `none`), read from logind's
  `/run/systemd/shutdown/scheduled` (works on systemd 249 / 22.04), with
  `busctl` as a fallback. JSON gains `reboot_scheduled` (ISO 8601 or null) and
  `reboot_schedule_state`. New `schedule-reboot --status` (read-only, `--json`)
  and `--cancel` (`shutdown -c`, root). Scheduling or cancelling that fails now
  exits 1, as does `apply --reboot` when the reboot could not be scheduled.
  The unused `scheduler.reboot_now()` was removed.
- **`npm audit` now actually audits each project (#154).** It ran in kevward's
  own working directory, so every Node.js project looked clean. It now runs
  inside the project (`util.run(..., cwd=)`), and an npm error or unreadable
  output shows as an INFO "npm audit could not run ... (not checked)" instead
  of no findings.
- **`[audit] allowed_outbound` (#155).** Expected outbound connections, e.g.
  `["tor:9001"]` (`<process glob>:<port glob>[@<cidr>]`), are no longer listed
  as "unexpected outbound" every run; they are counted in one `allowed
  outbound: N (tor:9001)` line (CLI, HTML; JSON `audit_allowed_outbound`). A
  shell-owned socket is always reported. Malformed or too-broad entries
  (`*:*`) are ignored with a LOW audit finding.
- **Processes still running replaced code.** The apt check now reads
  `/proc/*/maps` and reports units whose processes still execute a library or
  binary that an update has replaced on disk (e.g. `sshd` on the pre-update
  `libssl.so.3` after a USN), with the restart that fixes each one
  (`systemctl restart ssh`, `daemon-reexec` for PID 1, re-login for
  sessions). Medium when a service still maps an old TLS library, low
  otherwise. Catches what `reboot required: no` misses when needrestart did
  not restart everything. Read-only; as non-root only the caller's own
  processes are checked and the finding says so. Containers (other mount
  namespaces) are skipped.
- The publish workflow runs on `ubuntu-24.04` instead of `ubuntu-latest`,
  like CI, so a runner-label change cannot alter the release build.

## 0.13.0

Signal accuracy: the KEV table and the findings list now say what there is to
act on. Old kernel, PHP, Laravel-ecosystem, node and Apache rows that stayed
"possible" are decided from evidence on the host; one advisory is one finding;
a cold host fills its CVE cache in one run.

- **Fewer "possible" KEV rows (#62).** On hokaku (jammy) all 15 rows that
  stayed "possible" are now decided from evidence on the host:
  - Decade-old kernel CVEs (Dirty COW, CVE-2013-2094, ...) become
    `n/a (release)` when Ubuntu records the upstream fix in an older kernel
    series than the running one (`fixed upstream in 4.9~rc2, before linux
    5.15`). Ubuntu's upstream tags like `3.9~rc8` now parse.
  - Laravel, Ignition, Livewire and PHPMailer rows are decided from every
    `composer.lock` under the app roots, and node's systeminformation from
    `package-lock.json` plus global npm modules: `fixed`, `applicable` or
    `n/a` with the paths and versions as the reason. A WordPress
    `wp-includes/` (bundled PHPMailer) or a `node_modules/` without a lock
    file blocks `n/a`.
  - PHP-FPM CVE-2019-11043 and PHP-CGI CVE-2012-1823 are `n/a (config)` when
    every installed PHP branch is 7.4+ / 5.5+ (Ubuntu tracks them under
    php7.x / php5, which never matched a php8.x host).
  - Apache CVE-2019-0211 (Ubuntu tracks only bionic, upstream
    "needs-triage") is `n/a (release)` when the installed apache2 is at or
    past the upstream fix 2.4.39. Such CVEs live in a small, sourced
    `UPSTREAM_FIXED` table, used only when this release is untracked.
  - The reason line reads "why:" for fixed/applicable rows.
- **apt findings are grouped by source package (#143).** One advisory that
  touches several binary packages (e.g. glibc: libc6, libc-bin, locales, ...)
  is now one finding, `glibc 2.35-0ubuntu3.15 → 2.35-0ubuntu3.18 (6 packages)`,
  instead of one per package, so the severity counts reflect things to act on.
  `apply` still installs every package. Security findings link to the Ubuntu
  Security Notices for that source package. **JSON:** findings gain
  `packages` (all binary packages, empty for single-package findings) and
  `url`; finding counts drop accordingly. In the HTML report a grouped apt
  row drops the packages a service plugin already lists (0.12.11's
  de-duplication), e.g. `apache2-data, apache2-utils (2 packages)`.
- **Cold hosts resolve the KEV table in one run (#66).** Uncached Ubuntu CVE
  lookups now run 4 at a time (`[trends] fetch_workers`, 1–16), still inside
  the time budget, and `kevward trends --warm-cache` does one long pass (up to
  10 min) to fill the cache after install. Exit code 1 if rows are still
  unchecked or the cache is not writable.

## 0.12.11

Reports that say why: the reboot reason, block-set sizes, the drop window on
Ubuntu 22.04, and one row per package update. CI now tests 22.04, 24.04 and
26.04 explicitly.

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
- **Firewall drop window on Ubuntu 22.04.** The report's "firewall drops
  (since …)" fell back to "since last ruleset load" on jammy: systemd 249
  rejects `systemctl show --timestamp=unix` (added in 251). kevward now falls
  back to `ActiveEnterTimestampMonotonic` + the boot time from `/proc/stat`.
- **Block-set sizes next to the drop counts.** The "firewall drops" line now
  shows how many entries each set holds (`evidence blocklist 4 (51 entries)`),
  so a low drop count can be told apart from an emptied set. JSON: new
  `attackers.firewall_sizes` (needs root; omitted otherwise).
- **Why a reboot is required (#144).** The header and the "Reboot required"
  finding name the packages from `reboot-required.pkgs`
  (`reboot required: YES (libc6)`). When only userspace packages asked
  (no kernel, firmware or microcode), the finding drops from medium to low:
  needrestart has already restarted the services. JSON: new
  `reboot_packages` and `reboot_kind` (`kernel` / `userspace` / `""`).
- **One row per package update in the HTML report.** A package owned by a
  service plugin (e.g. `apache2` under `apache`) was also listed by the
  host-wide `apt` plugin, so one Apache update showed as `high: 6` instead of
  4. The `apt` duplicate is no longer shown or counted; a note says how many
  were folded. JSON and `apply` are unchanged.

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
