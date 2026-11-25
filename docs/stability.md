# Stability policy (1.x)

From 1.0, kevward follows these rules for everything other programs rely on:
JSON output, `report.json`, CLI flags, `config.toml` keys, exit codes and the
ssh-gate protocol.

## Within 1.x (minor and patch releases)

- **May add:** JSON keys, enum values (a new `severity` or `kind` is not
  expected but a new `applicability` label is possible), CLI flags, config
  keys, ssh-gate ops and error codes.
- **Does not:** remove or rename a JSON key, change a key's type, remove a CLI
  flag or config key, change what an exit code means.
- Finding `title` / `detail` wording is for humans and may change.

## Removing or renaming

- Announced in CHANGELOG under "Deprecated" at least one minor release before
  it happens.
- A JSON removal or rename bumps `schema_version` (and the ssh-gate
  `protocol` for incompatible gate changes).
- A deprecated config key keeps working and produces a config warning
  (MEDIUM finding) until it is removed.

## Clients

- Check `schema_version` (JSON) or `protocol` (ssh-gate); refuse a higher one
  you do not know.
- Ignore unknown keys, treat unknown enum values as the nearest known one
  (an unknown severity as `info`), and unknown ssh-gate error codes as a
  generic error.

## Exit codes

| code | meaning |
|---|---|
| 0 | success. Read-only commands (`check`, `report`, `audit`, `harden check`, `trends`) return 0 whatever they find: the findings are the signal |
| 1 | the action ran and failed (an install, `firewall list` with the table missing, a reboot schedule) |
| 2 | refused before doing anything: invalid config for a command with side effects, policy forbids it, bad arguments, not root; ssh-gate: the response has `ok: false` |
| 3 | `apply --expect-plan`: the plan changed, nothing was installed |
| 4 | `apply --job`: another apply or self.update holds the lock |
| 5 | `apply`: refused because truthgate enforces and no maintenance window is open (#247) |

`argparse` usage errors also exit 2.
