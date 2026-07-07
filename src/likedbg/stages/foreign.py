"""Foreign-kernel pipeline stages: adopt a provided kernel (Manifest-free) and optionally
repack its initramfs with an exploit. See ADR-0010."""

from __future__ import annotations

from pathlib import Path

from likedbg.constants import VOLUME_MOUNT
from likedbg.foreign import ForeignKernel
from likedbg.pipeline import PipelineContext


class ForeignAdoptStage:
    """Inject a pre-resolved ForeignKernel into the ctx (no Manifest, no .config)."""

    name = "foreign-adopt"

    def __init__(self, *, foreign: ForeignKernel, qemu_extra: tuple[str, ...]) -> None:
        self._foreign = foreign
        self._qemu_extra = qemu_extra

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        fk = self._foreign
        ctx.kernel_image = fk.image
        ctx.rootfs_image = fk.initramfs
        # gdb mounts the vmlinux's host dir at VOLUME_MOUNT (/ksrc) read-only; the in-container
        # path is /ksrc/<basename>. The mount source is passed to build_foreign_pipeline.
        ctx.vmlinux = Path(VOLUME_MOUNT) / fk.vmlinux.name
        ctx.foreign_cmdline = fk.cmdline
        ctx.qemu_extra = self._qemu_extra
        if ctx.recorder is not None:
            ctx.recorder.record_kernel_paths(  # type: ignore[attr-defined]
                config=None,
                system_map="",
                vmlinux=str(fk.vmlinux),
                image=str(fk.image),
            )
        return ctx
