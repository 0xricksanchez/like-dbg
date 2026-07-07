"""Pipeline context + stage protocol + runner. The insertion seam for all stages."""

from __future__ import annotations

import time
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Protocol
from typing import runtime_checkable

from loguru import logger

from likedbg.config import DebuggeeCfg
from likedbg.config import Settings
from likedbg.host_profile import HostProfile

if TYPE_CHECKING:
    from likedbg.debug_profiles import RunResolution


@dataclass
class PipelineContext:
    settings: Settings
    host: HostProfile
    kernel_archive: Path | None = None
    kernel_root: Path | None = None
    kernel_status: str | None = None
    rootfs_image: Path | None = None
    vmlinux: Path | None = None
    kernel_image: Path | None = None
    build_label: str | None = None
    rootfs_label: str | None = None
    # B1/B2 debug-profile fields (all optional, defaulted)
    run_resolution: RunResolution | None = None
    effective_debuggee: DebuggeeCfg | None = None
    extra_boot_args: tuple[str, ...] = field(default_factory=tuple)
    foreign_cmdline: str | None = None
    qemu_extra: tuple[str, ...] = field(default_factory=tuple)
    recorder: object | None = None  # TODO: type as RunRecorder once run_artifacts (Task 12) exists
    kernel_release: str | None = None
    config_host: Path | None = None


@runtime_checkable
class Stage(Protocol):
    name: str

    def run(self, ctx: PipelineContext) -> PipelineContext: ...

    def should_skip(self, ctx: PipelineContext) -> bool: ...


def _fmt_duration(seconds: float) -> str:
    """Format elapsed seconds as compact whole seconds or minutes+seconds."""
    s = int(seconds)
    return f"{s // 60}m{s % 60}s" if s >= 60 else f"{s}s"


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        self._stages = stages

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self._stages:
            if stage.should_skip(ctx):
                logger.debug(f"skipping stage: {stage.name}")
                continue
            logger.info(f"stage {stage.name}: started")
            t0 = time.monotonic()
            ctx = stage.run(ctx)
            logger.info(f"stage {stage.name}: done ({_fmt_duration(time.monotonic() - t0)})")
        return ctx
