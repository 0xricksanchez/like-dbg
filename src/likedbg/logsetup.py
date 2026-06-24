"""loguru sink configuration: a human-facing stderr sink (all CLI paths) and a full-detail
per-run file (run / --use paths only). Named `logsetup`, not `logging`, to avoid shadowing
the stdlib module."""

from __future__ import annotations

import sys
from datetime import UTC
from datetime import datetime
from pathlib import Path

from loguru import logger

_STDERR_FMT = "<green>{time:HH:mm:ss}</green> <level>{level: <5}</level> {message}"
_FILE_FMT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <7} | {name}:{function}:{line} - {message}"


def configure_stderr(*, verbose: bool) -> None:
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "INFO", format=_STDERR_FMT, colorize=True)


def _prune_old_logs(logs: Path, *, keep: int) -> None:
    existing = sorted(logs.glob("run-*.log"))  # UTC-timestamp names sort chronologically
    for old in existing[: max(0, len(existing) - keep)]:
        old.unlink(missing_ok=True)


def _point_latest(link: Path, target: Path) -> None:
    try:
        link.unlink(missing_ok=True)
        link.symlink_to(target.name)  # relative — same dir
    except OSError:
        pass  # symlinks unavailable (e.g. Windows) — non-fatal


def add_run_logfile(workspace: Path) -> Path:
    logs = workspace / "artifacts" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    _prune_old_logs(logs, keep=20)
    run_log = logs / f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.log"
    logger.add(run_log, level="DEBUG", format=_FILE_FMT)
    _point_latest(logs / "latest.log", run_log)
    return run_log
