"""Merge a gdb-live crash snapshot (crash.gdb.json) into the primary CrashEvent,
or synthesize a primary CrashEvent from it when the console yielded no fatal onset."""

from __future__ import annotations

from typing import Any

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import GdbLive

# gdb `stopped_at` breakpoint label -> crash kind. Unknown labels fall back to "oops".
_STOPPED_AT_KIND: dict[str, str] = {
    "panic": "panic",
    "die": "oops",
    "oops_enter": "oops",
    "kasan_report": "kasan",
    "ubsan_epilogue": "ubsan",
}


def _primary_index(events: list[CrashEvent]) -> int | None:
    if not events:
        return None
    for i, ev in enumerate(events):
        if ev.fatal:
            return i
    return 0


def _to_gdb_live(gdb_live: dict[str, Any]) -> GdbLive:
    return GdbLive(
        stopped_at=str(gdb_live.get("stopped_at", "")),
        registers={str(k): str(v) for k, v in dict(gdb_live.get("registers", {})).items()},
        backtrace=[str(x) for x in gdb_live.get("backtrace", [])],
    )


def merge_gdb_live(events: list[CrashEvent], gdb_live: dict[str, Any]) -> list[CrashEvent]:
    idx = _primary_index(events)
    if idx is None or not gdb_live or "stopped_at" not in gdb_live:
        return events
    ev = events[idx]
    ev.gdb_live = _to_gdb_live(gdb_live)
    if "gdb-live" not in ev.source:
        ev.source.append("gdb-live")
    return events


def synthesize_from_gdb_live(gdb_live: dict[str, Any]) -> CrashEvent | None:
    """Build a standalone primary CrashEvent from a gdb-live snapshot.

    Used when gdb halts the guest at the fault (e.g. `panic()` entry) before the
    kernel prints its onset banner to the serial console, so `parse_console` sees
    no fatal event. A crash breakpoint only traps on a real fault, so the snapshot
    is itself a crash.
    """
    if not isinstance(gdb_live, dict) or "stopped_at" not in gdb_live:
        return None
    stopped_at = str(gdb_live.get("stopped_at", ""))
    kind = _STOPPED_AT_KIND.get(stopped_at, "oops")
    live = _to_gdb_live(gdb_live)
    if live.backtrace:
        first = live.backtrace[0]
        title = (first[2:].lstrip() if first.startswith("#0") else first).strip()
    else:
        title = f"kernel crash trapped at {stopped_at}"
    return CrashEvent(kind=kind, fatal=True, title=title, gdb_live=live, source=["gdb-live"])
