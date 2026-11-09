# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#70: newer-release notice — version comparison, fail-soft lookup, finding."""

from __future__ import annotations

import json

from kevward.config import Config
from kevward.integrations import update_check as uc
from kevward.model import Severity


def test_is_newer():
    assert uc.is_newer("0.12.4", "0.12.5")
    assert uc.is_newer("0.12.5", "0.13.0")
    assert uc.is_newer("0.9.9", "0.10.0")          # numeric, not lexical
    assert not uc.is_newer("0.12.5", "0.12.5")
    assert not uc.is_newer("0.12.5", "0.12.4")
    assert not uc.is_newer("1.0", "1.0.0")
    assert not uc.is_newer("0.12.5", "0.13.0rc1")  # pre-release ignored...
    assert uc.is_newer("0.13.0rc1", "0.13.0")      # ...unless already on one
    assert not uc.is_newer("0.12.5", "garbage")


def test_finding_when_newer():
    f = uc.update_findings("0.12.4", "0.12.5", prefix="/opt/kevward")
    assert len(f) == 1 and f[0].severity is Severity.INFO
    assert f[0].title == "kevward 0.12.4 installed, 0.12.5 available"
    assert "install -U kevward" in f[0].detail


def test_no_finding_when_current_or_unknown():
    assert uc.update_findings("0.12.5", "0.12.5") == []
    assert uc.update_findings("0.12.5", "") == []


def _redirect_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(uc, "_cache_file", lambda: tmp_path / "pypi.json")


def test_lookup_caches_and_fails_soft(monkeypatch, tmp_path):
    _redirect_cache(monkeypatch, tmp_path)

    class Resp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return json.dumps({"info": {"version": "9.9.9"}}).encode()

    monkeypatch.setattr(uc.urllib.request, "urlopen", lambda req, timeout=5: Resp())
    assert uc.latest_release() == "9.9.9"

    def offline(req, timeout=5):
        raise OSError("no network")

    monkeypatch.setattr(uc.urllib.request, "urlopen", offline)
    assert uc.latest_release() == "9.9.9"          # fresh cache, no network
    (tmp_path / "pypi.json").unlink()
    assert uc.latest_release() is None             # offline, no cache: silent


def test_config_opt_out(tmp_path):
    p = tmp_path / "k.toml"
    p.write_text("[update]\ncheck = false\n")
    assert Config.load(p).update.check is False
    assert Config().update.check is True
