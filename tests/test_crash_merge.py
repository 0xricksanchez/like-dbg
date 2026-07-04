"""Tests for gdb-live merge into primary CrashEvent."""

from likedbg.crash.merge import merge_gdb_live
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
