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

    def __init__(self, *, launch: Callable[[str], None], debuggee_image: str) -> None:
        self._launch = launch
        self._debuggee_image = debuggee_image

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        argv = build_qemu_argv(
            eff,
            ctx.host,
            target_arch=ctx.host.target_arch,
            kernel_image=ctx.kernel_image,
            rootfs=ctx.rootfs_image,
            extra_boot_args=ctx.extra_boot_args,
        )
        if ctx.host.debuggee_mode == "in-container":
            # kernel Image read-only (QEMU only reads -kernel); rootfs disk read-write (QEMU's -drive).
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            cmd = qemu_container_command(
                argv,
                image=self._debuggee_image,
                ro_mounts=[ctx.kernel_image],
                rw_mounts=rw_mounts,
                gdbstub_port=eff.gdb_port,
                network_mode=ctx.host.network_mode,
                kvm=ctx.host.accel == "kvm",
            )
        else:
            cmd = qemu_pane_command(argv)
        if ctx.recorder is not None:
            ctx.recorder.set_status("launching")  # type: ignore[attr-defined]
            ctx.recorder.record_command("qemu", shell=cmd, argv=argv)  # type: ignore[attr-defined]
        try:
            self._launch(cmd)
        except Exception:
            if ctx.recorder is not None:
                ctx.recorder.set_status("launch-failed", message="debuggee launch failed")  # type: ignore[attr-defined]
            raise
        return ctx
