# kevward JSON output (schema_version 1)

Every JSON document kevward prints or writes carries `"schema_version": 1`
and `kevward_version`. The [stability policy](stability.md) says what may
change within 1.x. Keys not listed here may appear; clients ignore keys they
do not know.

## Common types

**Finding** (in `services[].findings`, `audit`, and `findings` of `audit` /
`harden check`):

| key | type | notes |
|---|---|---|
| `service` | string | plugin / area, e.g. `apt`, `nginx`, `audit`, `kevward` |
| `kind` | enum | `vulnerability`, `security_update`, `minor_upgrade`, `config` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `title`, `detail` | string | human-readable; wording may change |
| `current_version`, `fixed_version`, `cve`, `ref`, `url`, `origin` | string or null | |
| `reboot_required` | bool | |
| `packages` | list of string | |

Other keys of a finding (apt details) may be present.

## `check --json`, `report --json`, `apply` (RunResult)

| key | type | null? |
|---|---|---|
| `schema_version` | int | no |
| `kevward_version`, `host`, `generated_at` (ISO 8601 UTC), `os` | string | no |
| `reboot_required`, `reboot_pending` | bool | no |
| `reboot_packages` | list of string | no |
| `reboot_kind` | `kernel` / `userspace` / `""` | no |
| `reboot_scheduled` | string | yes |
| `reboot_schedule_state` | `scheduled` / `none` / `unknown` | no |
| `config_source`, `config_error` | string | yes |
| `config_warnings` | list of string | no |
| `services` | list of {`service`, `present`, `version`, `findings`, `actions`, `error`, `reboot_required`} | no |
| `attackers` | object (fail2ban, sshd, firewall state, `trends` with `--trends`) | yes |
| `audit` | list of Finding | yes (no `--audit`) |
| `audit_allowed_outbound`, `audit_allowed_forced` | object rule → count | no |
| `audit_rules` | object | no |
| `apt_refresh` | object (`state`, `seconds`, `error`, `lists_updated_at`) | no |

## `report.json` (written next to report.html; ssh-gate `report.get` `data`)

RunResult above, plus:

| key | type | null? |
|---|---|---|
| `summary` | object: `counts`, `act_now`, `apt_rows_deduplicated`, `audit_indicators`, `kev`, `attack` | no |
| `last_apply` | {`job_id`, `finished`, `state`, `installed_count`} | yes |

## `last-run.json`

`schema_version`, `started_at`, `finished_at`, `host`, `kevward_version`,
`ok` (bool), `error` (string or null), `report` (path).

## `trends --json`

`schema_version`, `kevward_version`, `host`, `generated_at`, `catalog_size`,
`cache_fresh`, `match_count`, `ransomware_linked`, `version_aware`,
`applicable_count`, `fixed_count`, `unchecked_count`, `not_applicable_count`,
`cve_cache`, `matches` (first 100). Each match has `applicability`:
`applicable`, `fixed`, `possible`, `unchecked`, `not_applicable`,
`na_release`, with `applicability_reason` where known.

## `audit --json`, `harden check --json`

```json
{"schema_version": 1, "kevward_version": "1.0.0", "host": "www",
 "generated_at": "2026-11-25T03:00:00+00:00", "findings": [ … ]}
```

`audit --json` also has `allowed_outbound_hits` and `allowed_forced_hits`
(rule → count). Before 1.0 these commands printed a bare list.

## Other commands

`firewall plan/apply --json`, `harden list --json`, `schedule status --json`,
`schedule-reboot --status --json`: their own keys plus `schema_version` and
`kevward_version`.

`setup --json`, `uninstall --json` and `kevward ssh-gate` use the ssh-gate
envelope `{"ok": true, "data": …}` / `{"ok": false, "error", "code"}`; see
[ssh-gate-protocol.md](ssh-gate-protocol.md).
