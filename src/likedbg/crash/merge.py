"""Merge a gdb-live crash snapshot (crash.gdb.json) into the primary CrashEvent."""

from __future__ import annotations

from typing import Any

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import GdbLive


def _primary_index(events: list[CrashEvent]) -> int | None:
    if not events:
        return None
    for i, ev in enumerate(events):
        if ev.fatal:
            return i
    return 0


def merge_gdb_live(events: list[CrashEvent], gdb_live: dict[str, Any]) -> list[CrashEvent]:
    idx = _primary_index(events)
    if idx is None or not gdb_live or "stopped_at" not in gdb_live:
        return events
    ev = events[idx]
    ev.gdb_live = GdbLive(
        stopped_at=str(gdb_live.get("stopped_at", "")),
        registers={str(k): str(v) for k, v in dict(gdb_live.get("registers", {})).items()},
        backtrace=[str(x) for x in gdb_live.get("backtrace", [])],
    )
    if "gdb-live" not in ev.source:
        ev.source.append("gdb-live")
    return events
