# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""#65: an unwritable system CVE cache falls back to a per-user cache, and is
reported when nothing is writable (instead of failing every write silently)."""

from __future__ import annotations

import json
import os
import time

from kevward.integrations import usn


def _blocked(tmp_path, name):
    # A path *under a regular file* can never be created, even by root.
    f = tmp_path / name
    f.write_text("")
    return f / "usn"


def test_system_dir_writable(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", tmp_path / "sys")
    st = usn.cache_status()
    assert st == {"dir": str(tmp_path / "sys"), "writable": True, "fallback": False}


def test_falls_back_to_user_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", _blocked(tmp_path, "sysfile"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    st = usn.cache_status()
    assert st["writable"] and st["fallback"]
    assert st["dir"] == str(tmp_path / "xdg" / "kevward" / "usn")
    usn._write_cache(usn._cache_path("CVE-2026-0001"), {"packages": []})
    assert (tmp_path / "xdg/kevward/usn/CVE-2026-0001.json").is_file()
    assert usn.cache_state("CVE-2026-0001") == "fresh"


def test_nothing_writable_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(usn, "CACHE_DIR", _blocked(tmp_path, "a"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(_blocked(tmp_path, "b")))
    st = usn.cache_status()
    assert st["writable"] is False
    usn._write_cache(usn._cache_path("CVE-2026-0002"), {"packages": []})  # no raise


def test_non_root_reads_newer_root_cache(monkeypatch, tmp_path):
    # Non-root view: the system dir exists (root filled it) but is read-only.
    sysd, xdg = tmp_path / "sys", tmp_path / "xdg"
    sysd.mkdir()
    monkeypatch.setattr(usn, "CACHE_DIR", sysd)
    monkeypatch.setenv("XDG_CACHE_HOME", str(xdg))
    real = usn._writable
    monkeypatch.setattr(usn, "_writable", lambda d: d != sysd and real(d))
    user = xdg / "kevward" / "usn"
    user.mkdir(parents=True)
    (user / "CVE-2026-0003.json").write_text(json.dumps({"from": "user"}))
    past = time.time() - 3600
    os.utime(user / "CVE-2026-0003.json", (past, past))
    (sysd / "CVE-2026-0003.json").write_text(json.dumps({"from": "system"}))
    assert usn.cached_cve("CVE-2026-0003") == {"from": "system"}
    # and a newer per-user entry wins over an older system one
    os.utime(sysd / "CVE-2026-0003.json", (past - 60, past - 60))
    assert usn.cached_cve("CVE-2026-0003") == {"from": "user"}
