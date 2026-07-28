"""Boot-time stage: point the Debuggee at this session's copy-on-write overlay rather than the
shared rootfs image, so concurrent sessions do not fight over QEMU's write lock. See ADR-0019."""

from __future__ import annotations

from typing import Any

from likedbg.pipeline import PipelineContext
from likedbg.rootfs_overlay import ensure_overlay


class RootfsOverlayStage:
    name = "rootfs-overlay"

    def __init__(self, container: Any, *, debuggee_image: str) -> None:
        self._c = container
        self._image = debuggee_image

    def should_skip(self, ctx: PipelineContext) -> bool:
        # A foreign guest boots an initramfs (-initrd), which QEMU never write-locks, so it has
        # nothing to overlay. Without a session name there is nothing to key an overlay on.
        img = ctx.rootfs_image
        return img is None or not ctx.session_name or ".cpio" in img.name

    def run(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.rootfs_image is not None
        base = ctx.rootfs_image
        ctx.rootfs_base = base
        ctx.rootfs_image = ensure_overlay(self._c, base=base, session_name=ctx.session_name, image=self._image)
        return ctx
