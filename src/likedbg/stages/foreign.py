"""Foreign-kernel pipeline stages: adopt a provided kernel (Manifest-free) and optionally
repack its initramfs with an exploit. See ADR-0010."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from likedbg.constants import VOLUME_MOUNT
from likedbg.foreign import ForeignKernel
from likedbg.foreign import repack_initramfs
from likedbg.pipeline import PipelineContext


class ForeignAdoptStage:
    """Inject a pre-resolved ForeignKernel into the ctx (no Manifest, no .config)."""

    name = "foreign-adopt"

    def __init__(
        self,
        *,
        foreign: ForeignKernel,
        qemu_extra: tuple[str, ...],
        foreign_net: bool = True,
        foreign_net_iface: str = "eth0",
    ) -> None:
        self._foreign = foreign
        self._qemu_extra = qemu_extra
        self._foreign_net = foreign_net
        self._foreign_net_iface = foreign_net_iface

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
        ctx.foreign_net = self._foreign_net
        ctx.foreign_net_iface = self._foreign_net_iface
        ctx.qemu_extra = self._qemu_extra
        if ctx.recorder is not None:
            ctx.recorder.record_kernel_paths(  # type: ignore[attr-defined]
                config=None,
                system_map="",
                vmlinux=str(fk.vmlinux),
                image=str(fk.image),
            )
        return ctx


class ForeignRepackStage:
    """Repack the foreign initramfs with the exploit at /exploit; runs only when exploit is set.
    Stamp-guarded inside repack_initramfs: an unchanged exploit reuses the previous repack."""

    name = "foreign-repack"

    def __init__(
        self,
        container: Any,
        *,
        foreign: ForeignKernel,
        exploit: Path | None,
        image: str,
        out_dir: Path,
        workspace: Path,
        exploit_flags: tuple[str, ...] = (),
    ) -> None:
        self._c = container
        self._foreign = foreign
        self._exploit = exploit
        self._image = image
        self._out_dir = out_dir
        self._workspace = workspace
        self._exploit_flags = exploit_flags

    def should_skip(self, ctx: PipelineContext) -> bool:
        if self._exploit is not None and self._foreign.initramfs is None:
            logger.warning(
                "foreign kernel has no initramfs to repack: exploit "
                f"{self._exploit} will NOT be delivered into the guest"
            )
        return self._exploit is None or self._foreign.initramfs is None

    def run(self, ctx: PipelineContext) -> PipelineContext:
        assert self._exploit is not None and self._foreign.initramfs is not None
        repacked = repack_initramfs(
            self._c,
            initramfs=self._foreign.initramfs,
            exploit=self._exploit,
            arch=ctx.host.target_arch,
            out=self._out_dir / "initramfs.repacked.cpio.gz",
            image=self._image,
            workspace=self._workspace,
            extra_flags=self._exploit_flags,
        )
        ctx.rootfs_image = repacked
        return ctx
