# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#127: the MongoDB plugin (/etc/mongod.conf read as text, no YAML dep)."""

from __future__ import annotations

from kevward.plugins import mongodb as mg

# /etc/mongod.conf as the mongodb-org package ships it.
STOCK = """\
# mongod.conf

# for documentation of all options, see:
#   http://docs.mongodb.org/manual/reference/configuration-options/

# Where and how to store data.
storage:
  dbPath: /var/lib/mongodb
#  engine:
#  wiredTiger:

# where to write logging data.
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log

# network interfaces
net:
  port: 27017
  bindIp: 127.0.0.1


# how the process runs
processManagement:
  timeZoneInfo: /usr/share/zoneinfo

#security:

#operationProfiling:
"""


def test_parse_conf():
    c = mg.parse_conf(STOCK)
    assert c["net.bindIp"] == "127.0.0.1" and c["net.port"] == "27017"
    assert c["systemLog.path"] == "/var/log/mongodb/mongod.log"
    assert "security" not in " ".join(c)
    c = mg.parse_conf('net:\n    bindIp: "0.0.0.0"  # everyone\nsecurity:\n'
                      "    authorization: 'enabled'\n")
    assert c == {"net.bindIp": "0.0.0.0", "security.authorization": "enabled"}


def test_stock_is_local():
    assert mg.exposed_without_auth(mg.parse_conf(STOCK)) is None


def test_open_without_auth():
    conf = STOCK.replace("bindIp: 127.0.0.1", "bindIp: 127.0.0.1,0.0.0.0")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) == "0.0.0.0"
    conf = STOCK.replace("bindIp: 127.0.0.1", "bindIp: '::'")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) == "::"
    conf = STOCK.replace("bindIp: 127.0.0.1", "bindIpAll: true")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) == "all interfaces (bindIpAll)"
    conf = conf.replace("#security:", "security:\n  authorization: disabled")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) is not None


def test_auth_protects():
    open_ = STOCK.replace("bindIp: 127.0.0.1", "bindIp: 0.0.0.0")
    conf = open_.replace("#security:", "security:\n  authorization: enabled")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) is None
    conf = open_.replace("#security:", "security:\n  keyFile: /etc/mongo/keyfile")
    assert mg.exposed_without_auth(mg.parse_conf(conf)) is None


def test_check_reads_config(monkeypatch, tmp_path):
    monkeypatch.setattr("kevward.plugins._apt._simulate_upgrade", lambda: [])
    cfg = tmp_path / "mongod.conf"
    monkeypatch.setattr(mg, "CONFIG", cfg)
    assert mg.MongodbPlugin().check() == []                 # no config file
    cfg.write_text(STOCK.replace("bindIp: 127.0.0.1", "bindIp: 0.0.0.0"))
    fs = mg.MongodbPlugin().check()
    assert [f.title for f in fs] == ["MongoDB listens on 0.0.0.0 without access control"]


def test_not_installed_is_silent(monkeypatch):
    monkeypatch.setattr("kevward.plugins._apt._pkg_version", lambda p: None)
    p = mg.MongodbPlugin()
    assert p.detect() is False
    rep = p.report(do_apply=False, dry_run=True)
    assert rep.present is False and rep.error is None
    assert p.service_unit == "mongod.service" and p.kev_terms == ["mongodb"]
    assert p.packages == ["mongodb-org-server", "mongodb-org-mongos", "mongodb-org"]
