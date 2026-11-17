# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#85: which docroots / PHP-FPM are actually served; EOL, unused and
autoremovable FPMs. Pure parsers and findings; no host."""

from __future__ import annotations

from datetime import date

from kevward.model import Severity
from kevward.plugins import _webserve as ws
from kevward.plugins.php import php_findings

# Trimmed `nginx -T` from a hokaku-like host: sites-enabled/default is a
# symlink, which `grep -r` missed on 2026-11-09; nginx -T prints it anyway.
NGINX_T = """\
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
user www-data;
http {
    server_tokens off;
    include /etc/nginx/sites-enabled/*;
}
# configuration file /etc/nginx/sites-enabled/default:
upstream php_backend { server unix:/run/php/php8.3-fpm.sock; }
server {
    listen 443 ssl;
    server_name hokaku.example.jp www.hokaku.example.jp;
    root /var/www/hokaku_server/public;  # app
    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
server {
    listen 8080;
    server_name api.example.jp;
    location / { proxy_pass http://127.0.0.1:3000; }
    location /legacy { fastcgi_pass php_backend; }
}
server { listen 80 default_server; server_name _; return 301 https://$host$request_uri; }
"""

SYSTEMCTL = """\
php8.1-fpm.service loaded active running The PHP 8.1 FastCGI Process Manager
php8.2-fpm.service loaded active running The PHP 8.2 FastCGI Process Manager
php8.3-fpm.service loaded active running The PHP 8.3 FastCGI Process Manager
php8.4-fpm.service loaded active running The PHP 8.4 FastCGI Process Manager
"""

AUTOREMOVE = """\
NOTE: This is only a simulation!
Remv php8.3-fpm [8.3.27-1+ubuntu22.04.1+deb.sury.org+1]
Remv php8.3-cli [8.3.27-1+ubuntu22.04.1+deb.sury.org+1]
Remv linux-headers-5.15.0-200 [5.15.0-200.210]
"""

POLICY_PPA = """\
php8.1-fpm:
  Installed: 8.1.33-1+ubuntu22.04.1+deb.sury.org+1
  Candidate: 8.1.33-1+ubuntu22.04.1+deb.sury.org+1
  Version table:
 *** 8.1.33-1+ubuntu22.04.1+deb.sury.org+1 500
        500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu jammy/main amd64 Packages
        100 /var/lib/dpkg/status
     8.1.2-1ubuntu2.22 500
        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
"""
POLICY_UBUNTU = """\
php8.1-fpm:
  Installed: 8.1.2-1ubuntu2.22
  Version table:
 *** 8.1.2-1ubuntu2.22 500
        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
        100 /var/lib/dpkg/status
"""

TODAY = date(2026, 11, 13)


def test_parse_nginx_t_follows_dump_and_upstreams():
    servers, ups = ws.parse_nginx_t(NGINX_T)
    assert ups == {"php_backend": ["unix:/run/php/php8.3-fpm.sock"]}
    app = servers[0]
    assert app.names == ["hokaku.example.jp", "www.hokaku.example.jp"]
    assert app.roots == ["/var/www/hokaku_server/public"]
    assert app.php_versions(ups) == ["8.3"]
    api = servers[1]
    assert api.proxy == ["http://127.0.0.1:3000"] and api.php_versions(ups) == ["8.3"]
    lines = ws.served_summary(servers, ups)
    assert lines[0] == ("hokaku.example.jp www.hokaku.example.jp -> "
                        "root /var/www/hokaku_server/public; PHP 8.3 FPM")
    assert len(lines) == 2  # the redirect-only default server serves nothing


def test_apache_and_systemctl_and_apt_parsers():
    conf = ('<FilesMatch ".+\\.php$">\n'
            '  SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n'
            '</FilesMatch>\n# SetHandler proxy:unix:/run/php/php7.4-fpm.sock\n')
    assert ws.apache_fpm_versions(conf) == ["8.2"]
    assert ws.parse_running_fpm(SYSTEMCTL) == ["8.1", "8.2", "8.3", "8.4"]
    assert ws.parse_autoremove(AUTOREMOVE) == ["php8.3-fpm", "php8.3-cli",
                                               "linux-headers-5.15.0-200"]
    assert ws.parse_policy_origin(POLICY_PPA) == "ppa.launchpadcontent.net/ondrej/php"
    assert ws.parse_policy_origin(POLICY_UBUNTU) == "archive.ubuntu.com jammy-updates"
    assert ws.parse_policy_origin("php8.9-fpm:\n  Installed: (none)\n") is None


def test_referenced_versions_unknown_when_config_unreadable():
    assert ws.referenced_versions(None, None, nginx_present=True,
                                  apache_present=False) is None
    assert ws.referenced_versions(NGINX_T, None, True, False) == {"8.3"}
    assert ws.referenced_versions(None, None, False, False) == set()


def test_hokaku3_like_findings():
    fs = php_findings("php", cli="8.4", running=["8.1", "8.2", "8.3", "8.4"],
                      referenced={"8.3"}, autoremove=ws.parse_autoremove(AUTOREMOVE),
                      origins={"8.1": "ppa.launchpadcontent.net/ondrej/php",
                               "8.2": "ppa.launchpadcontent.net/ondrej/php"},
                      today=TODAY)
    by = {f.title: f for f in fs}
    eol81 = by["PHP 8.1 past end of security support (2025-12)"]
    assert eol81.severity == Severity.MEDIUM
    assert "not referenced by the web server" in eol81.detail
    assert "ondrej/php" in eol81.detail
    assert by["PHP 8.2 nearing end of security support (2026-12)"].severity == Severity.LOW
    unused = by["PHP-FPM running but not used by the web server: 8.1, 8.2, 8.4"]
    assert unused.severity == Severity.INFO and "php8.1-fpm php8.2-fpm php8.4-fpm" in unused.detail
    auto = by["php8.3-fpm serves the web server but `apt autoremove` would remove it"]
    assert auto.severity == Severity.MEDIUM
    assert "apt-mark manual php8.3-cli php8.3-fpm" in auto.detail
    assert not any("8.3 past" in t or "8.4 past" in t for t in by)


def test_unknown_references_skip_unused_and_autoremove():
    fs = php_findings("php", cli=None, running=["8.1", "8.3"], referenced=None,
                      autoremove=["php8.3-fpm"], origins={}, today=TODAY)
    titles = [f.title for f in fs]
    assert titles == ["PHP 8.1 past end of security support (2025-12)"]
    assert "php8.1-fpm (running)" in fs[0].detail


def test_cli_only_host_keeps_old_behaviour():
    fs = php_findings("php", cli="8.1", running=[], referenced=set(), autoremove=[],
                      origins={}, today=TODAY)
    assert [f.title for f in fs] == ["PHP 8.1 past end of security support (2025-12)"]
    assert fs[0].detail.startswith("CLI.")
