#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.
#
# Root integration test (#117) on a disposable CI runner: install kevward the
# way hosts run it (/opt/kevward venv), then exercise the root-only paths
# end to end - the report service in its real systemd sandbox, the firewall
# round trip, setup / ssh-gate / uninstall / setup --restore, and a broken
# config. Every bug of 2026-11-22..25 (#204, #227, #231, #243, #244, #246)
# lived in one of these paths and none was visible to unit tests.
#
# Usage: sudo ci/integration.sh <repo-dir>      (destructive: CI runners only)

set -euo pipefail
REPO=$(cd "${1:-.}" && pwd)
K=/opt/kevward/bin/kevward
PY=/opt/kevward/bin/python
CONSOLE=kvconsole
TMP=$(mktemp -d)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
[ -n "${CI:-}" ] || { echo "refusing: CI is not set (this changes the system)"; exit 2; }

step() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }
jget() { "$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {'d': d}))" "$@"; }
gate() {  # gate <role> <json>  -> one JSON line, as the console would get it
    local role=$1 req=$2
    if [ "$role" = read ]; then
        sudo -u "$CONSOLE" env SSH_CONNECTION="203.0.113.5 50000 192.0.2.10 22" \
            "$K" ssh-gate --role read <<<"$req"
    else
        sudo -u "$CONSOLE" env SSH_CONNECTION="203.0.113.5 50000 192.0.2.10 22" \
            sudo -n "$K" ssh-gate --role operate <<<"$req"
    fi
}

install_kevward() {
    python3 -m venv /opt/kevward
    /opt/kevward/bin/pip install -q --upgrade pip
    /opt/kevward/bin/pip install -q "$REPO"
    "$K" --version
}

step "system"
. /etc/os-release && echo "$PRETTY_NAME"
python3 --version
systemctl --version | head -1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null
nft --version

step "install into /opt/kevward"
install_kevward
mkdir -p /etc/kevward
cat > /etc/kevward/config.toml <<'EOF'
[update]
check = false

[ssh_gate]
enabled = true
self_update = true
EOF

step "check / report / audit as root, JSON parses"
"$K" check -c /etc/kevward/config.toml >/dev/null
"$K" report -c /etc/kevward/config.toml --json -o "$TMP/r.html" > "$TMP/r.json"
jget "$TMP/r.json" "sorted(d)[:5]"
test -s "$TMP/r.html"
test -s "$TMP/r.json" && jget "$TMP/r.json" "d['host']" >/dev/null
"$K" audit -c /etc/kevward/config.toml --json > "$TMP/a.json" || true   # findings exit non-zero
jget "$TMP/a.json" "type(d).__name__"

step "console user and keys"
id "$CONSOLE" >/dev/null 2>&1 || useradd --create-home --shell /bin/sh "$CONSOLE"
ssh-keygen -q -t ed25519 -N "" -C ci-read -f "$TMP/read"
ssh-keygen -q -t ed25519 -N "" -C ci-operate -f "$TMP/operate"
READ=$(cat "$TMP/read.pub"); OPER=$(cat "$TMP/operate.pub")

step "setup (keys, sudoers, timer)"
"$K" setup --console-user "$CONSOLE" --read-key "$READ" --operate-key "$OPER" \
    --ssh-gate --timer --json > "$TMP/setup.json"
jget "$TMP/setup.json" "d['ok']" | grep -qx True || { cat "$TMP/setup.json"; fail "setup"; }
[ "$(grep -c 'ssh-gate --role' /home/$CONSOLE/.ssh/authorized_keys)" = 2 ] || fail "gate lines"
visudo -cf /etc/sudoers.d/kevward-ssh-gate

step "ssh-gate read and operate, client address recorded (#214)"
gate read '{"op":"version"}' > "$TMP/v.json"; jget "$TMP/v.json" "d['data']['version']"
gate operate '{"op":"reboot.status"}' > "$TMP/rb.json"
jget "$TMP/rb.json" "d['ok']" | grep -qx True || { cat "$TMP/rb.json"; fail "reboot.status (#203)"; }
gate operate '{"op":"schedule.status"}' > "$TMP/ss.json"
jget "$TMP/ss.json" "d['data']['warnings']" | tee /dev/stderr | grep -qx '\[\]' \
    || fail "schedule.status warnings"

step "report service in its real sandbox (#227 #231 #246)"
systemctl start kevward-report.service          # oneshot: returns when done
journalctl -u kevward-report.service --no-pager -n 20 || true
R=/var/log/kevward/report.json
test -s "$R" || fail "no report.json from the timer unit"
jget "$R" "d['apt_refresh']" | tee /dev/stderr
jget "$R" "d['apt_refresh']['state']" | grep -qx ok || fail "apt-get update in the unit (#227/#231)"
if grep -q "the report runs without the real" "$R"; then fail "report sandbox hides /home or /tmp (#246)"; fi
if grep -q "no authorized_keys entry uses it" "$R"; then fail "false 'no gate key' (#237/#246)"; fi
jget "$R" "d['schema_version']" | grep -qx 1 || fail "schema_version"

step "firewall round trip (#77 #243 #244)"
"$K" firewall apply -c /etc/kevward/config.toml --yes --block 192.0.2.1 --allow 198.51.100.0/24
nft list table inet kevward >/dev/null
nft -c -f /etc/kevward/firewall.nft || fail "saved ruleset does not parse (#77)"
test -f /var/lib/kevward/firewall.json || fail "in-use record (#243)"
"$K" firewall list -c /etc/kevward/config.toml | head -5

step "harden plan / apply / revert"
"$K" harden plan -c /etc/kevward/config.toml || true
"$K" harden apply -c /etc/kevward/config.toml --yes || true
"$K" harden revert -c /etc/kevward/config.toml --yes || true

step "uninstall (keeps config and state), snapshot written (#236)"
"$K" uninstall --json > "$TMP/u-dry.json" || true
jget "$TMP/u-dry.json" "d['data']['actions'][0]['kind']" | grep -qx snapshot || fail "dry run"
"$K" uninstall --yes --json > "$TMP/u.json" || { cat "$TMP/u.json"; fail "uninstall (#234)"; }
test ! -e /opt/kevward || fail "/opt/kevward left behind"
if nft list table inet kevward >/dev/null 2>&1; then fail "table left behind"; fi
SNAP=/var/lib/kevward/setup-snapshot.json
jget "$SNAP" "d['firewall']" | grep -qx True || fail "snapshot firewall (#243)"
[ "$(grep -c 'ssh-gate --role' /home/$CONSOLE/.ssh/authorized_keys || true)" = 0 ] || fail "gate lines left"

step "reinstall + setup --restore brings everything back (#236 #243)"
install_kevward
"$K" setup --restore --json > "$TMP/restore.json" || { cat "$TMP/restore.json"; fail "restore"; }
[ "$(grep -c 'ssh-gate --role' /home/$CONSOLE/.ssh/authorized_keys)" = 2 ] || fail "keys not restored"
test -f /etc/sudoers.d/kevward-ssh-gate || fail "sudoers not restored"
systemctl is-enabled kevward-report.timer | grep -qx enabled || fail "timer not restored"
nft list table inet kevward >/dev/null || fail "firewall not restored (#243)"
gate operate '{"op":"version"}' > "$TMP/v2.json"; jget "$TMP/v2.json" "d['ok']" | grep -qx True

step "missing firewall is reported (#244)"
nft delete table inet kevward
systemctl start kevward-report.service
grep -q "kevward firewall not loaded" "$R" || fail "no HIGH finding for a missing table (#244)"
"$K" firewall apply -c /etc/kevward/config.toml --yes --block 192.0.2.1 >/dev/null

step "broken config: check survives, apply refuses (#104)"
cp /etc/kevward/config.toml "$TMP/config.good"
printf '[policy\napply_minor = yes\n' > /etc/kevward/config.toml
"$K" check -c /etc/kevward/config.toml --json > "$TMP/bad.json" || true
grep -qi "config" "$TMP/bad.json" || fail "no config finding"
set +e; "$K" apply -c /etc/kevward/config.toml --yes >/dev/null 2>&1; rc=$?; set -e
[ "$rc" = 2 ] || fail "apply with a broken config exited $rc, want 2"
cp "$TMP/config.good" /etc/kevward/config.toml

step "ok"
