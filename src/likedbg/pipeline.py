"""Pipeline context + stage protocol + runner. The insertion seam for all stages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from typing import runtime_checkable

from loguru import logger

from likedbg.config import Settings
from likedbg.host_profile import HostProfile


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


@runtime_checkable
class Stage(Protocol):
    name: str

    def run(self, ctx: PipelineContext) -> PipelineContext: ...

    def should_skip(self, ctx: PipelineContext) -> bool: ...


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        self._stages = stages

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self._stages:
            if stage.should_skip(ctx):
                logger.debug(f"skipping stage: {stage.name}")
                continue
            logger.info(f"running stage: {stage.name}")
            ctx = stage.run(ctx)
        return ctx
