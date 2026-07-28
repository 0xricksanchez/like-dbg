"""Debuggee stage: launch QEMU, native host process (arm64-on-Mac HVF) or inside the debuggee
container (x86_64-on-Mac TCG / Linux KVM), chosen by host.debuggee_mode."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from likedbg.errors import BuildError
from likedbg.launchers import qemu_container_command
from likedbg.launchers import qemu_pane_command
from likedbg.pipeline import PipelineContext
from likedbg.qemu import build_qemu_argv


class DebuggeeStage:
    name = "debuggee"

    def __init__(self, *, launch: Callable[[str], None], debuggee_image: str, workspace: Path) -> None:
        self._launch = launch
        self._debuggee_image = debuggee_image
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        console_log = None
        if eff.capture_console and ctx.recorder is not None:
            console_log = ctx.recorder.console_raw  # type: ignore[attr-defined]
        share_host_dir = None
        if eff.share:
            share_host_dir = self._workspace / eff.share_dir
            share_host_dir.mkdir(parents=True, exist_ok=True)
        argv = build_qemu_argv(
            eff,
            ctx.host,
            target_arch=ctx.host.target_arch,
            kernel_image=ctx.kernel_image,
            rootfs=ctx.rootfs_image,
            extra_boot_args=ctx.extra_boot_args,
            console_log=console_log,
            share_host_dir=share_host_dir,
            foreign_cmdline=ctx.foreign_cmdline,
            foreign_mitigation_overrides=ctx.foreign_mitigation_overrides,
            foreign_net=ctx.foreign_net,
            foreign_net_iface=ctx.foreign_net_iface,
            qemu_extra=ctx.qemu_extra,
        )
        if ctx.host.debuggee_mode == "in-container":
            # kernel Image read-only (QEMU only reads -kernel); rootfs disk read-write (QEMU's -drive).
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            extra_rw = tuple(
                p for p in (console_log.parent if console_log is not None else None, share_host_dir) if p is not None
            )
            cmd = qemu_container_command(
                argv,
                image=self._debuggee_image,
                ro_mounts=[ctx.kernel_image],
                rw_mounts=rw_mounts,
                gdbstub_port=eff.gdbstub_port,
                network_mode=ctx.host.network_mode,
                kvm=ctx.host.accel == "kvm",
                ssh_port=eff.ssh_port if eff.guest_net else None,
                extra_rw_dirs=extra_rw,
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
