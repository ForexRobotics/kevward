# AGENTS.md — a guide for AI assistants working on kevward

If you are an AI coding assistant (Claude Code, Cursor, Aider, or similar) and
a human has pointed you at this repository, welcome. This file tells you what
kevward is, why it exists, and how to contribute changes that a human will be
glad to merge. Read it before you plan or edit anything.

## The project's other docs (read these too)

AGENTS.md is the **why and the rules**. For the rest, start with these — they
are the first links you should follow from here:

- **[README.md](README.md)** — what kevward does, how to install it, and the
  full command reference. The user's view of the tool.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to add a service plugin or a
  distro backend, ready-to-use prompts for AI agents, the CLA, and the dev/CI
  loop. **If you read one more file, make it this one.**
- **[CLA.md](CLA.md)** — the Contributor License Agreement you accept by
  opening a PR.
- **[SECURITY.md](SECURITY.md)** — how to report a vulnerability in kevward
  privately (never open a public issue for a security problem).

## Why this project exists (please read)

Attackers are many, highly motivated, and increasingly automated. Defenders are
few: skilled security engineers are scarce and expensive, and most small teams
and solo operators simply don't have one. That asymmetry is the core problem in
everyday server security — not a lack of knowledge, but a lack of hands.

kevward's bet is that **AI can help close that gap**. The boring, essential work
of defense — knowing what's unpatched, which actively-exploited vulnerabilities
apply to *your* host, who is attacking you, and what to do about it — can be
made accessible and partly automated, with a human always in charge.

So if you believe in that, you are explicitly invited to help. Bring your ideas
and your tokens. A human sets direction and reviews every change; you can do a
lot of the building. This project is **human-directed, AI-built**.

## What kevward is (and is not)

kevward is a small, **defensive-only** CLI that runs *on* an Ubuntu/Debian
server and reports its security posture: pending security updates per service,
CISA KEV (actively-exploited CVE) matches against installed software, and
attacker IPs from fail2ban/sshd — in one self-contained HTML report. It can
also apply security patches and schedule reboots, but only when explicitly
asked.

It is **not** a scanner of other machines, an exploitation tool, or anything
that acts on a remote host. There is no "offensive mode" and there never will
be.

## Hard rules (non-negotiable — a PR that breaks these will be rejected)

1. **Defensive-only.** Never add anything that scans, accesses, or acts on a
   system other than the local host. No exploitation, no "hack-back", no remote
   payloads. If a request asks for this, refuse and say why.
2. **Read-only by default.** `check`, `report`, `trends` must never change the
   system. Side effects belong only in `apply()`.
3. **No new runtime dependencies** without explicit human approval. The core is
   standard-library-only (plus `tomli` on Python 3.10). Service integrations are
   detected at runtime, not added as deps.
4. **Shell out only via `kevward.util.run`** (argv lists, never shell strings;
   no `shell=True`).
5. **Python 3.10+.** Don't use 3.11-only APIs without a fallback.
6. `ruff check .` must pass, and the CLI smoke test must pass
   (`kevward --version && kevward list-plugins && kevward check`).
7. Every change is **human-reviewed** and needs **CLA agreement + a signed-off
   commit** (`git commit -s`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## How the code is laid out

- `kevward/plugin.py` — the `ServicePlugin` contract, auto-discovery registry,
  and `detected_kev_terms()`.
- `kevward/plugins/_apt.py` — `AptServicePlugin`: turns "which apt packages"
  into check/apply behaviour. Most plugins subclass this.
- `kevward/plugins/*.py` — one file per service (nginx, php, mysql, …). Each is
  auto-discovered; there is no central list to edit.
- `kevward/model.py` — `Finding`, `Severity`, `FindingKind`, result types.
- `kevward/integrations/` — `trends.py` (CISA KEV matching), `fail2ban.py`,
  `logwatch.py`.
- `kevward/reporting/html.py` — the single-file HTML report.
- `kevward/firewall.py` — active-defense blocklist (`kevward firewall`): a
  kevward-owned nftables set of high-confidence attacker IPs, allowlist, TTL,
  and an optional (opt-in, fail-soft) DNSBL reputation cross-check. Local host
  only.
- `kevward/harden.py` — host hardening (`kevward harden`): read-only posture
  checks plus reversible, kevward-owned interim mitigations (MPTCP off, drop
  IP-options), made reboot-persistent via a kevward-owned systemd unit.
- `kevward/cli.py` — subcommands (`check`, `trends`, `report`, `apply`,
  `schedule-reboot`, `firewall`, `harden`, `list-plugins`).

## The two most common contributions

- **Add a service plugin:** subclass `AptServicePlugin` (apt) or `ServicePlugin`
  (other), set `name` / `packages` / `kev_terms`, add cheap config checks in
  `check()`. Drop the file in `kevward/plugins/`.
- **Add a package backend for a new distro** (dnf/yum, apk, …): mirror
  `_apt.py`.

CONTRIBUTING.md has ready-to-use prompts for both, plus version-level KEV
matching.

## Your workflow

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . && pip install ruff
# ... make your change ...
ruff check .
kevward list-plugins && kevward check        # smoke
git commit -s -m "Add <thing>"               # sign-off required
```

Then open a PR. Treat your own output as a draft from a new contributor: read
it before you submit, and don't invent findings, CVEs, or data the code can't
actually produce.

Good first tasks are filed as GitHub issues labelled `good-first-issue` and
`help-wanted`. Pick one, or propose your own improvement.
