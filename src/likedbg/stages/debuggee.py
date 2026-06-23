"""Debuggee stage: launch QEMU — native host process (arm64-on-Mac HVF) or inside the debuggee
container (x86_64-on-Mac TCG / Linux KVM), chosen by host.debuggee_mode."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.launchers import qemu_container_command
from likedbg.launchers import qemu_pane_command
from likedbg.pipeline import PipelineContext
from likedbg.qemu import build_qemu_argv


class DebuggeeStage:
    name = "debuggee"

    def __init__(self, *, send: Callable[[str], None], debuggee_image: str) -> None:
        self._send = send
        self._debuggee_image = debuggee_image

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        argv = build_qemu_argv(ctx.settings, ctx.host, kernel_image=ctx.kernel_image, rootfs=ctx.rootfs_image)
        mounts = [p for p in (ctx.kernel_image, ctx.rootfs_image) if p is not None]
        if ctx.host.debuggee_mode == "in-container":
            cmd = qemu_container_command(argv, image=self._debuggee_image, mounts=mounts)
        else:
            cmd = qemu_pane_command(argv)
        self._send(cmd)
        return ctx
