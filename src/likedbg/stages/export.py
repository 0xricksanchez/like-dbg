"""Export stage: copy built single-file artifacts out of the kernel-source volume
to the host workspace, so native (host) QEMU can read them. No-op in bind mode.

Only ``Image`` is exported to the host.  ``vmlinux`` stays inside the volume:
the debugger container mounts the volume read-only and reads vmlinux directly
from there (spec §4.6), so exporting it to a host path would make it
unreachable to in-container gdb."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg.constants import BASE_IMAGE
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.errors import CacheError
from likedbg.errors import ContainerError
from likedbg.pipeline import PipelineContext

_OUT_MOUNT = "/out"


class ArtifactExporter:
    name = "export"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return ctx.host.storage_mode != "volume"

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None or ctx.kernel_image is None:
            raise BuildError("missing build label / image in context", remedy="run Build first")
        label = ctx.build_label
        out_dir = self._workspace / "artifacts" / label
        host_image = out_dir / "Image"
        if host_image.exists():
            logger.info(f"export cache hit: {host_image}")
            ctx.kernel_image = host_image
            return ctx
        out_dir.mkdir(parents=True, exist_ok=True)
        image_in_tree = str(ctx.kernel_image)
        vmlinux_in_tree = f"{VOLUME_MOUNT}/{label}/vmlinux"
        volumes = {
            self._volume: {"bind": VOLUME_MOUNT, "mode": "ro"},
            str(out_dir): {"bind": _OUT_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            try:
                self._c.exec(container, f"test -e {vmlinux_in_tree}")
                self._c.exec(container, f"test -e {image_in_tree}")
            except ContainerError as exc:
                raise CacheError(
                    f"in-volume artifact missing for {label}",
                    remedy=f"--clean {label}",
                ) from exc
            self._c.exec(container, f"cp {image_in_tree} {_OUT_MOUNT}/Image")
        finally:
            self._c.stop(container)
        ctx.kernel_image = host_image
        # ctx.vmlinux intentionally left unchanged (container path in volume)
        return ctx
