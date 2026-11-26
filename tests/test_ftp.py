# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#134: the ProFTPD and vsftpd plugins (configs read as text)."""

from __future__ import annotations

import pytest

from kevward.model import Severity
from kevward.plugins import proftpd as pf
from kevward.plugins import vsftpd as vs

# /etc/vsftpd.conf as Ubuntu ships it (trimmed).
VSFTPD_STOCK = """\
# Run standalone?
listen=NO
listen_ipv6=YES
# Allow anonymous FTP? (Disabled by default).
anonymous_enable=NO
local_enable=YES
#write_enable=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
"""

# /etc/proftpd/proftpd.conf as Ubuntu ships it (trimmed).
PROFTPD_STOCK = """\
Include /etc/proftpd/modules.conf
UseIPv6\t\t\t\ton
ServerName\t\t\t"Debian"
#Include /etc/proftpd/tls.conf
# A basic anonymous configuration, no upload directories.
# <Anonymous ~ftp>
#   User\t\t\t\tftp
# </Anonymous>
Include /etc/proftpd/conf.d/
"""


def _vs(text: str) -> list[Severity]:
    return [s for s, _, _ in vs.classify(vs.parse_conf(text))]


def _pf(text: str) -> list[Severity]:
    return [s for s, _, _ in pf.classify(text)]


def test_vsftpd():
    assert _vs(VSFTPD_STOCK) == [Severity.LOW]
    assert _vs(VSFTPD_STOCK.replace("ssl_enable=NO", "ssl_enable=YES")) == []
    assert _vs(VSFTPD_STOCK.replace("anonymous_enable=NO", "anonymous_enable=yes")) == [
        Severity.MEDIUM, Severity.LOW]
    assert _vs("#anonymous_enable=YES\nssl_enable=YES\n") == []     # defaults: NO


def test_proftpd():
    assert _pf(PROFTPD_STOCK) == [Severity.LOW]
    anon = PROFTPD_STOCK + "<Anonymous ~ftp>\n  User ftp\n</Anonymous>\n"
    assert _pf(anon) == [Severity.MEDIUM, Severity.LOW]
    assert _pf(PROFTPD_STOCK + "<IfModule mod_tls.c>\nTLSEngine  on\n</IfModule>\n") == []
    assert _pf(PROFTPD_STOCK + "TLSEngine off\n") == [Severity.LOW]


def test_proftpd_follows_includes(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "anon.conf").write_text("<Anonymous /srv/ftp>\n</Anonymous>\n")
    (tmp_path / "tls.conf").write_text("TLSEngine on\n")
    (tmp_path / "unused.conf").write_text("<Anonymous /x>\n</Anonymous>\n")
    main = tmp_path / "proftpd.conf"
    main.write_text("Include tls.conf\n#Include unused.conf\nInclude conf.d/\n")
    text = pf.read_config(main)
    assert "/srv/ftp" in text and "/x" not in text
    assert _pf(text) == [Severity.MEDIUM]
    assert pf.read_config(tmp_path / "missing.conf") == ""


@pytest.mark.parametrize("mod, cls, pkgs, unit, kev", [
    (pf, "ProftpdPlugin", ["proftpd-basic", "proftpd-core"], "proftpd.service", ["proftpd"]),
    (vs, "VsftpdPlugin", ["vsftpd"], "vsftpd.service", ["vsftpd"]),
])
def test_not_installed_is_silent(monkeypatch, mod, cls, pkgs, unit, kev):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = getattr(mod, cls)()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert (p.packages, p.service_unit, p.kev_terms) == (pkgs, unit, kev)
