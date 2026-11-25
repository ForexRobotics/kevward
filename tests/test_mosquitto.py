# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#128: the Mosquitto plugin (config read as text, broker never contacted)."""

from __future__ import annotations

from kevward.model import Severity
from kevward.plugins import mosquitto as mq

# /etc/mosquitto/mosquitto.conf as Ubuntu/Debian ship it.
UBUNTU_DEFAULT = """\
# Place your local configuration in /etc/mosquitto/conf.d/
pid_file /run/mosquitto/mosquitto.pid
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
include_dir /etc/mosquitto/conf.d
"""


def _sev(text: str, major: int = 2) -> list[Severity]:
    return [s for s, _, _ in mq.classify_listeners(mq.parse_listeners(text, major))]


def test_default_config_is_local_only():
    assert mq.parse_listeners(UBUNTU_DEFAULT) == []
    assert _sev(UBUNTU_DEFAULT) == []


def test_open_listener_with_anonymous():
    conf = "listener 1883\nallow_anonymous true\n"
    assert _sev(conf) == [Severity.MEDIUM, Severity.LOW]
    title = mq.classify_listeners(mq.parse_listeners(conf))[0][1]
    assert "all interfaces:1883" in title


def test_anonymous_default_is_false_in_2x():
    assert _sev("listener 1883\npassword_file /etc/mosquitto/passwd\n") == [Severity.LOW]


def test_tls_listener():
    conf = ("listener 8883\ncertfile /etc/mosquitto/certs/s.crt\n"
            "keyfile /etc/mosquitto/certs/s.key\npassword_file /etc/mosquitto/passwd\n")
    assert _sev(conf) == []
    assert _sev("listener 8883\npsk_hint hint\n") == []


def test_loopback_and_unix_socket_are_local():
    assert _sev("listener 1883 127.0.0.1\nallow_anonymous true\n") == []
    assert _sev("listener 1883 localhost\nallow_anonymous true\n") == []
    assert _sev("listener 1883 ::1\nallow_anonymous true\n") == []
    assert _sev("listener 0 /run/mosquitto.sock\nallow_anonymous true\n") == []
    assert _sev("listener 1883\nbind_interface lo\nallow_anonymous true\n") == []
    assert _sev("listener 1883\nbind_interface eth0\nallow_anonymous true\n") == [
        Severity.MEDIUM, Severity.LOW]


def test_global_allow_anonymous_applies_to_every_listener():
    # per_listener_settings false (default): position does not matter.
    conf = "allow_anonymous true\nlistener 1883 127.0.0.1\nlistener 1884 0.0.0.0\n"
    assert _sev(conf) == [Severity.MEDIUM, Severity.LOW]


def test_per_listener_settings():
    conf = ("per_listener_settings true\n"
            "listener 1883 127.0.0.1\nallow_anonymous true\n"
            "listener 1884\nallow_anonymous false\npassword_file /etc/mosquitto/p\n")
    assert _sev(conf) == [Severity.LOW]
    conf = ("per_listener_settings true\n"
            "listener 1883 127.0.0.1\nallow_anonymous true\nlistener 1884\n")
    assert _sev(conf) == [Severity.LOW]          # 1884 falls back to the 2.x default


def test_deprecated_port_and_bind_address():
    assert _sev("port 1883\nallow_anonymous true\n") == [Severity.MEDIUM, Severity.LOW]
    assert _sev("port 1883\nbind_address 127.0.0.1\nallow_anonymous true\n") == []


def test_1x_defaults():
    assert _sev(UBUNTU_DEFAULT, major=1) == [Severity.MEDIUM, Severity.LOW]
    assert _sev("allow_anonymous false\n", major=1) == [Severity.LOW]


def test_comments_and_blank_lines():
    assert _sev("# listener 1883\n\n#allow_anonymous true\n") == []


def test_major_version():
    assert mq.major_version("mosquitto 2.0.18-1ubuntu1") == 2
    assert mq.major_version("mosquitto 1.6.9-1") == 1
    assert mq.major_version("mosquitto 1:2.0.11-1") == 2
    assert mq.major_version(None) == 2


def test_read_config_follows_include_dir(tmp_path):
    d = tmp_path / "conf.d"
    d.mkdir()
    (d / "b.conf").write_text("allow_anonymous true\n")
    (d / "a.conf").write_text("listener 1883\n")
    (d / "README").write_text("listener 9999\n")
    main = tmp_path / "mosquitto.conf"
    main.write_text(f"persistence true\ninclude_dir {d}\n")
    text = mq.read_config(main)
    assert text.index("listener 1883") < text.index("allow_anonymous true")
    assert "9999" not in text
    assert _sev(text) == [Severity.MEDIUM, Severity.LOW]
    assert mq.read_config(tmp_path / "missing.conf") == ""


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = mq.MosquittoPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert p.kev_terms == ["mosquitto"] and p.service_unit == "mosquitto.service"
