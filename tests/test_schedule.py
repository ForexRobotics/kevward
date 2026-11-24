

# --- #227: the read-only report service must still write these ----------------

def test_service_and_dropin_allow_apt_and_state(tmp_path):
    from kevward import schedule as sch

    for text in (sch.render_service("/opt/kevward/bin/kevward"), sch.render_service_dropin()):
        line = next(ln for ln in text.splitlines() if ln.startswith("ReadWritePaths="))
        assert sch.missing_rw_paths(line.split("=", 1)[1]) == []
        assert "-/var/lib/apt/lists" in line and "-/var/lib/kevward" in line


def test_plan_always_rewrites_service_dropin(tmp_path):
    from kevward import schedule as sch

    paths = sch.Paths(unit_dir=tmp_path, state_file=tmp_path / "s.json")
    paths.service.write_text("[Service]\nReadWritePaths=/var/log/kevward /var/cache/kevward\n")
    paths.timer.write_text("x")
    plan = sch.plan_install(paths, "07:00", "20min", "/opt/kevward/bin/kevward")
    written = {p: new for p, _t, new in plan}
    assert paths.service not in written                      # the operator's unit stays
    assert written[paths.service_dropin] is True
    paths.service_dropin.parent.mkdir()
    paths.service_dropin.write_text("old")
    plan = sch.plan_install(paths, "07:00", "20min", "/opt/kevward/bin/kevward")
    assert {p: new for p, _t, new in plan}[paths.service_dropin] is False   # updated


def test_status_warns_on_old_unit():
    from kevward import schedule as sch

    props = {"UnitFileState": "enabled", "ActiveState": "active",
             "RandomizedDelayUSec": "20min", "FixedRandomDelay": "yes"}
    old = "/var/log/kevward /var/cache/kevward"
    w = sch.status_warnings(props, True, old)
    assert any("cannot write /var/lib/kevward, /var/lib/apt/lists, /var/cache/apt" in x
               for x in w)
    new = " ".join("-" + p for p in sch.RW_PATHS)
    assert sch.status_warnings(props, True, new) == []
    assert sch.status_warnings(props, True, None) == []      # unit not loaded: no claim


# --- #235: refresh, and install keeps the recorded time --------------------------

def test_recorded_and_install_keeps_time(tmp_path, monkeypatch):
    from kevward import schedule as sch

    paths = sch.Paths(unit_dir=tmp_path, state_file=tmp_path / "s.json")
    assert sch.recorded(paths) == (sch.DEFAULT_AT, sch.DEFAULT_JITTER)
    paths.state_file.write_text('{"at": "05:30", "jitter": "10min"}')
    assert sch.recorded(paths) == ("05:30", "10min")
    paths.state_file.write_text('{"at": "99:99", "jitter": "x"}')
    assert sch.recorded(paths) == (sch.DEFAULT_AT, sch.DEFAULT_JITTER)
    paths.state_file.write_text('{"at": "05:30", "jitter": "10min"}')
    ok, msgs = sch.install(dry_run=True, paths=paths, exe="/opt/kevward/bin/kevward")
    assert ok and any("OnCalendar=*-*-* 05:30:00" in m for m in msgs)


def test_refresh_only_touches_the_managed_dropin(tmp_path, monkeypatch):
    from kevward import schedule as sch

    paths = sch.Paths(unit_dir=tmp_path, state_file=tmp_path / "s.json")
    ok, msgs = sch.refresh(paths=paths)
    assert ok and "nothing to refresh" in msgs[0] and not paths.service_dropin.exists()
    paths.service.write_text("[Service]\nExecStart=/x\n")
    monkeypatch.setattr(sch, "is_root", lambda: True)
    monkeypatch.setattr(sch, "have", lambda c: False)
    ok, msgs = sch.refresh(paths=paths)
    assert ok and msgs == [f"created {paths.service_dropin}"]
    assert paths.service.read_text() == "[Service]\nExecStart=/x\n"
    assert not paths.timer.exists() and not paths.dropin.exists()
    assert sch.refresh(paths=paths)[1] == [f"{paths.service_dropin} is up to date"]
