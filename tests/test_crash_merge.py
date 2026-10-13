"""Tests for gdb-live merge into primary CrashEvent."""

from likedbg.crash.merge import merge_gdb_live
from likedbg.crash.merge import synthesize_from_gdb_live
from likedbg.crash.model import CrashEvent


def _events():
    return [
        CrashEvent(kind="warn", fatal=False, title="w"),
        CrashEvent(kind="oops", fatal=True, title="o"),
    ]


def test_merge_attaches_to_first_fatal():
    gl = {"stopped_at": "die", "registers": {"pc": "0x1"}, "backtrace": ["#0 die", "#1 vuln"]}
    out = merge_gdb_live(_events(), gl)
    assert out[1].gdb_live is not None and out[1].gdb_live.stopped_at == "die"
    assert out[1].source == ["console", "gdb-live"]
    assert out[0].gdb_live is None


def test_merge_empty_is_noop():
    out = merge_gdb_live(_events(), {})
    assert all(e.gdb_live is None for e in out)


def test_synthesize_from_gdb_live_panic():
    gl = {
        "stopped_at": "panic",
        "registers": {"x0": "0x1"},
        "backtrace": ["#0  panic (fmt=...) at kernel/panic.c:285", "#1 sysrq_handle_crash ..."],
    }
    ev = synthesize_from_gdb_live(gl)
    assert ev is not None
    assert ev.kind == "panic" and ev.fatal is True
    assert ev.gdb_live is not None and ev.gdb_live.stopped_at == "panic"
    assert ev.source == ["gdb-live"]
    assert "panic" in ev.title


def test_synthesize_kind_mapping():
    assert synthesize_from_gdb_live({"stopped_at": "die", "backtrace": []}).kind == "oops"
    assert synthesize_from_gdb_live({"stopped_at": "kasan_report", "backtrace": []}).kind == "kasan"
    assert synthesize_from_gdb_live({"stopped_at": "ubsan_epilogue", "backtrace": []}).kind == "ubsan"
    assert synthesize_from_gdb_live({"stopped_at": "something_new", "backtrace": []}).kind == "oops"


def test_synthesize_title_fallback_without_backtrace():
    ev = synthesize_from_gdb_live({"stopped_at": "die"})
    assert ev is not None and ev.title == "kernel crash trapped at die"


def test_synthesize_rejects_non_dict_or_missing_stopped_at():
    assert synthesize_from_gdb_live({}) is None
    assert synthesize_from_gdb_live({"registers": {}}) is None
    assert synthesize_from_gdb_live([]) is None  # type: ignore[arg-type]
