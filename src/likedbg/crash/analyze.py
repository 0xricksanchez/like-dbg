"""The single impure crash module: read a run dir, produce crash.json + crash.md,
flip run.json to `crashed`. Pure-host, Docker/tmux-free (ADR-0007)."""

from __future__ import annotations

import json
import re
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

from likedbg.crash.merge import merge_gdb_live
from likedbg.crash.merge import synthesize_from_gdb_live
from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport
from likedbg.crash.parse import parse_console
from likedbg.crash.render import render_json
from likedbg.crash.render import render_markdown
from likedbg.errors import CrashError

_RELEASE = re.compile(r"linux-(\d+\.\d+(?:\.\d+)?)")


def _kernel_release(build_label: str) -> str | None:
    m = _RELEASE.search(build_label)
    return m.group(1) if m else None


def _primary_index(events: list[CrashEvent]) -> int | None:
    for i, ev in enumerate(events):
        if ev.fatal:
            return i
    return 0 if events else None


def analyze_run(run_dir: Path) -> CrashReport | None:
    if not run_dir.is_dir():
        raise CrashError(f"run dir not found: {run_dir}", remedy="pass a valid run-id or `latest`")
    console = run_dir / "logs" / "console.raw"
    if not console.is_file():
        raise CrashError(f"no console log at {console}", remedy="this run predates crash capture or never booted")
    host: dict[str, Any] = json.loads((run_dir / "host.json").read_text())
    arch = str(host.get("target_arch", "x86_64"))
    run_json_path = run_dir / "run.json"
    run_json: dict[str, Any] = json.loads(run_json_path.read_text())
    build_label = str(run_json.get("build_label", ""))

    events = parse_console(console.read_text(), arch)
    gdb_path = run_dir / "crash" / "crash.gdb.json"
    if gdb_path.is_file():
        try:
            loaded = json.loads(gdb_path.read_text())
        except json.JSONDecodeError:
            loaded = None
        # Only use a JSON object; a valid-but-scalar file (e.g. `42`, `"x"`)
        # would make merge_gdb_live's membership test raise TypeError.
        if isinstance(loaded, dict):
            if any(e.fatal for e in events):
                # Console already has a fatal onset: attach the snapshot to it.
                events = merge_gdb_live(events, loaded)
            else:
                # gdb halted at the fault before the console onset printed (e.g.
                # panic() entry): the snapshot IS the crash -> synthesize primary.
                syn = synthesize_from_gdb_live(loaded)
                if syn is not None:
                    events.append(syn)

    # No console events AND no usable gdb-live snapshot: nothing to report.
    if not events:
        return None

    primary = _primary_index(events)
    report = CrashReport(
        arch=arch,
        build_label=build_label,
        kernel_release=_kernel_release(build_label),
        events=events,
        primary=primary,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    (run_dir / "crash.json").write_text(json.dumps(render_json(report), indent=2, sort_keys=True))
    (run_dir / "crash.md").write_text(render_markdown(report))

    prim = events[primary] if primary is not None else None
    if prim is not None and prim.fatal:
        run_json["status"] = "crashed"
        run_json.setdefault("status_history", []).append(
            {"status": "crashed", "at": report.generated_at, "message": prim.title}
        )
    run_json["crash"] = {
        "primary_class": prim.kind if prim else None,
        "title": prim.title if prim else None,
        "fatal": bool(prim.fatal) if prim else False,
        "events": len(events),
        "report_json": "crash.json",
        "report_md": "crash.md",
    }
    run_json_path.write_text(json.dumps(run_json, indent=2, sort_keys=True))
    return report
