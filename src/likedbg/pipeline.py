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
    from likedbg.run_artifacts import RunRecorder


@dataclass
class PipelineContext:
    settings: Settings
    host: HostProfile
    kernel_archive: Path | None = None
    kernel_root: Path | None = None
    source_root: Path | None = None
    srckey: str | None = None
    objdir: Path | None = None
    kernel_status: str | None = None
    rootfs_image: Path | None = None
    # The shared image an overlay is stacked on: QEMU opens a backing file read-only, so the
    # in-container debuggee has to mount it too. None when booting the image directly.
    rootfs_base: Path | None = None
    # This boot's tmux session, the key its rootfs overlay is named for.
    session_name: str = ""
    vmlinux: Path | None = None
    kernel_image: Path | None = None
    build_label: str | None = None
    rootfs_label: str | None = None
    build_was_cached: bool = False
    # debug-profile fields (all optional, defaulted)
    run_resolution: RunResolution | None = None
    effective_debuggee: DebuggeeCfg | None = None
    extra_boot_args: tuple[str, ...] = field(default_factory=tuple)
    foreign_cmdline: str | None = None
    foreign_net: bool = False
    foreign_net_iface: str = "eth0"
    # Names of explicitly configured [debuggee] mitigation toggles.  Foreign kernels otherwise
    # retain their supplied command line byte-for-byte.
    foreign_mitigation_overrides: tuple[str, ...] = field(default_factory=tuple)
    qemu_extra: tuple[str, ...] = field(default_factory=tuple)
    recorder: RunRecorder | None = None
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
