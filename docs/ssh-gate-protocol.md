<!-- SPDX-License-Identifier: CC0-1.0 -->

# ssh-gate protocol, version 1

This document and the test vectors in [`ssh-gate-protocol/vectors/`](ssh-gate-protocol/vectors/)
are dedicated to the public domain under
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/). Any
implementation may copy them. kevward's own code stays AGPL-3.0-or-later.

ssh-gate is how a management console (FR Security Centre) talks to a host:
over SSH, with keys whose `authorized_keys` line forces one command. kevward
implements it in Python (`kevward ssh-gate`), and truthgate in Rust
(`truthgate ssh-gate`). On a host with kevward, kevward's gate relays
`truthgate.*` ops to truthgate's gate. Hosts with kevward, truthgate or both
look the same to the console.

## Transport

- One SSH connection carries one request: one JSON object on stdin, read for
  at most **10 s** and at most **256 KiB** (262144 bytes).
- One response: one line of JSON on stdout, terminated by `\n`. Non-ASCII
  text is written as UTF-8, not `\u` escaped.
- Exit status 0 when `ok` is true, 2 otherwise. Clients use the JSON, not the
  exit status.
- Nothing else is written to stdout. stderr carries no protocol data.

## Request and response

```json
{"op": "report.get", "args": {"format": "json"}}
```

`op` is a string. `args` is an object; missing or `null` means `{}`.

```json
{"ok": true, "data": { … }}
{"ok": false, "error": "human-readable message", "code": "forbidden"}
```

### Error codes

| code | meaning |
|---|---|
| `forbidden` | gate disabled, role may not run the op, unsafe file, … |
| `bad_request` | not JSON / not UTF-8, wrong shape, invalid argument |
| `unknown_op` | the gate does not know the op |
| `too_large` | request over 256 KiB |
| `not_found` | the thing asked for does not exist |
| `conflict` | state changed since it was read (e.g. `expect_sha256`) |
| `internal` | anything else, including a bad response from a relayed gate |
| `not_installed` | the product a relayed op is for is not installed |
| `timeout` | a relayed gate did not answer in time |
| `unavailable` | (truthgate) its agent is not running |
| `precondition_failed` | (truthgate) e.g. its self-check fails |

**A client must treat an unknown code as a generic error.** Codes are added
without a protocol bump. `auth` is not a gate code: consoles use it for their
own SSH failures.

## Roles

There are two roles, fixed by the key, never by the request:

- **read**: runs as the console's SSH user.
- **operate**: **runs as root**. On kevward hosts it is reached through
  `sudo -n` and an exact sudoers line. Devices without sudo put the operate
  key in root's `authorized_keys` with a forced command and
  `PermitRootLogin forced-commands-only`.

```text
# ~/.ssh/authorized_keys of the console user
command="/opt/kevward/bin/kevward ssh-gate --role read --key-name console-read",restrict ssh-ed25519 AAAA… read
command="sudo -n /opt/kevward/bin/kevward ssh-gate --role operate --key-name console-operate",restrict ssh-ed25519 AAAA… operate

# /etc/sudoers.d/kevward-ssh-gate: exact commands, no wildcards
Defaults!/opt/kevward/bin/kevward env_keep += "SSH_CONNECTION"
console ALL=(root) NOPASSWD: /opt/kevward/bin/kevward ssh-gate --role operate --key-name console-operate
console ALL=(root) NOPASSWD: /opt/kevward/bin/kevward ssh-gate --role operate
```

`--key-name` (`[a-z0-9._-]{1,40}`) names the key for change logs, because
sshd does not tell a forced command which key was used. `env_keep` keeps the
client address (`SSH_CONNECTION`) through sudo.

## Namespaces

- Unprefixed ops belong to kevward (`version`, `report.get`, …).
- `truthgate.` ops belong to truthgate. `gate.` ops belong to the gate itself.
- A future product uses `<product>.`.

## `gate.capabilities` (both roles)

The console's first call on every connection:

```json
{"ok":true,"data":{"protocol":1,"role":"read","gate_user":"console",
  "products":{"kevward":{"version":"0.21.0","ops":["version","report.get","…"]},
              "truthgate":{"version":"0.1.0","protocol":1}}}}
```

- `gate_user`: the user this role's gate runs as (`root` for operate).
- `client` (kevward, optional): the caller's address and whether this host
  already trusts it, so a console can warn before a few failed logins ban it:
  `{"address", "fail2ban_ignored", "firewall_allowed", "configured",
  "seen_before", "known_source", "exempt_slot"}`; `null` = not in use / cannot
  tell. `exempt_slot` is the address in the calling key's fail2ban slot.
- kevward's `client.exempt` (operate, no arguments) puts the caller's own
  address into that slot, replacing the previous one, and returns
  `{"address", "replaced", "key", "fail2ban_ignored"}`; `client.exempt_clear`
  empties it (`{"cleared", "key"}`). Unnamed keys, no fail2ban, or an unknown
  caller address: `precondition_failed`.
- `products.kevward.ops`: the ops the calling role may run.
- `products.truthgate`: the `data` of `truthgate.capabilities`, only when
  truthgate is installed and answers within 5 s. Otherwise the key is absent;
  it is never an error.
- A gate that answers `unknown_op` predates this op: assume "kevward only,
  protocol 1" and use `version`.

## Relay (kevward → truthgate)

An op starting with `truthgate.` is not parsed by kevward:

- The exact request bytes go to `<truthgate_path> ssh-gate --role <role>` on
  stdin (argv, no shell). The role is the role of the incoming key. truthgate
  decides what each role may do.
- Before it runs, the binary must be a regular file, and it and every parent
  directory (also after resolving symlinks) must be root-owned and not group-
  or world-writable. Otherwise `forbidden`. Missing: `not_installed`.
- The environment is clean apart from `PATH`, `LANG`,
  `TRUTHGATE_GATE_CLIENT` (client address), `TRUTHGATE_GATE_ROLE` and, when
  known, `TRUTHGATE_GATE_KEY_ID` (the `--key-name`).
- It runs in its own process group. On timeout (120 s by default) the group
  gets SIGTERM, then SIGKILL 5 s later, and the answer is `timeout`.
- stderr is discarded.
- The response must be one line holding a JSON object with a boolean `ok`, at
  most 4 MiB. It is returned byte for byte. Anything else is `internal`.
- kevward logs only the op name and the result status of a relayed op.

## Versioning

`protocol` (in `version` and `gate.capabilities`) changes only for
incompatible changes. New ops, new optional arguments, new response keys and
new error codes do not change it. Clients ignore keys they do not know.

## Test vectors

Each file in `ssh-gate-protocol/vectors/` is one case:

```json
{"name": "unknown-op", "role": "read", "gate_enabled": true,
 "request": "{\"op\":\"no.such.op\"}",
 "expect": {"ok": false, "code": "unknown_op"}}
```

- The request is given as `request` (text), `request_hex` (raw bytes), or
  `request_repeat` (`text` repeated `count` times).
- `gate_enabled: false` means the host has not turned the gate on.
- `expect` compares `ok` and `code`, and, for `ok: true`, the keys listed in
  `data_keys` and the values in `data`. `error` texts are free.

kevward runs every vector in its test suite (`tests/test_protocol_vectors.py`).
