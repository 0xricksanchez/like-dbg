"""Debuggee stage: launch QEMU (native host subprocess for arm64-on-mac)."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext
from likedbg.qemu import build_qemu_argv


class DebuggeeStage:
    name = "debuggee"

    def __init__(self, *, launch: Callable[[list[str]], None]) -> None:
        self._launch = launch

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        argv = build_qemu_argv(ctx.settings, ctx.host, kernel_image=ctx.kernel_image, rootfs=ctx.rootfs_image)
        self._launch(argv)
        return ctx
