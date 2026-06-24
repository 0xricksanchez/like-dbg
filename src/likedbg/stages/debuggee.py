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
        if ctx.host.debuggee_mode == "in-container":
            # kernel Image read-only (QEMU only reads -kernel); rootfs disk read-write (QEMU's -drive).
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            cmd = qemu_container_command(
                argv,
                image=self._debuggee_image,
                ro_mounts=[ctx.kernel_image],
                rw_mounts=rw_mounts,
                gdbstub_port=ctx.settings.debuggee.gdb_port,
                network_mode=ctx.host.network_mode,
                kvm=ctx.host.accel == "kvm",
            )
        else:
            cmd = qemu_pane_command(argv)
        self._send(cmd)
        return ctx
