"""Tests for the analyze_run shell: reads a run dir, writes crash.json/md, flips status."""

import json
from pathlib import Path

import pytest

from likedbg.crash.analyze import analyze_run
from likedbg.errors import CrashError


def _mkrun(tmp_path: Path, console: str, *, gdb: dict | None = None, arch: str = "x86_64") -> Path:
    run = tmp_path / "runs" / "r1"
    (run / "logs").mkdir(parents=True)
    (run / "crash").mkdir()
    (run / "logs" / "console.raw").write_text(console)
    (run / "host.json").write_text(json.dumps({"target_arch": arch}))
    (run / "run.json").write_text(
        json.dumps({"status": "launched", "build_label": "linux-6.6.30-x", "status_history": []})
    )
    if gdb is not None:
        (run / "crash" / "crash.gdb.json").write_text(json.dumps(gdb))
    return run


PANIC = "[ 1.0] Kernel panic - not syncing: test\n[ 1.0] Call Trace:\n[ 1.0]  panic+0x1/0x2\n"
WARN = "[ 1.0] WARNING: CPU: 0 PID: 1 at kernel/sched/core.c:1 __schedule+0x1/0x2\n"


def test_analyze_writes_report_and_flips_status(tmp_path):
    run = _mkrun(tmp_path, PANIC, gdb={"stopped_at": "panic", "registers": {}, "backtrace": ["#0 panic"]})
    rep = analyze_run(run)
    assert rep is not None and rep.events[0].kind == "panic"
    cj = json.loads((run / "crash.json").read_text())
    assert cj["arch"] == "x86_64" and cj["kernel_release"] == "6.6.30"
    assert cj["events"][0]["gdb_live"]["stopped_at"] == "panic"
    assert (run / "crash.md").is_file()
    rj = json.loads((run / "run.json").read_text())
    assert rj["status"] == "crashed" and rj["crash"]["primary_class"] == "panic"


def test_analyze_no_crash_returns_none(tmp_path):
    run = _mkrun(tmp_path, "[ 0.1] Booting Linux\n[ 0.2] systemd started\n")
    assert analyze_run(run) is None
    assert not (run / "crash.json").exists()


def test_analyze_warn_only_records_event_without_flipping_status(tmp_path):
    run = _mkrun(tmp_path, WARN)
    rep = analyze_run(run)
    assert rep is not None and rep.events[0].kind == "warn" and rep.events[0].fatal is False
    assert (run / "crash.json").is_file()
    assert (run / "crash.md").is_file()
    rj = json.loads((run / "run.json").read_text())
    assert rj["status"] == "launched"
    assert rj["status_history"] == []
    assert rj["crash"]["primary_class"] == "warn"
    assert rj["crash"]["fatal"] is False


def test_analyze_tolerates_malformed_gdb_json(tmp_path):
    run = _mkrun(tmp_path, PANIC)
    (run / "crash" / "crash.gdb.json").write_text("{not valid json")
    rep = analyze_run(run)
    assert rep is not None
    assert rep.primary is not None
    assert rep.events[rep.primary].gdb_live is None
    assert (run / "crash.json").is_file()


def test_analyze_missing_run_dir_raises(tmp_path):
    with pytest.raises(CrashError):
        analyze_run(tmp_path / "nope")
