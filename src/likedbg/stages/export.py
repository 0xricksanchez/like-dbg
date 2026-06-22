"""Export stage: copy built single-file artifacts out of the kernel-source volume
to the host workspace, so native (host) QEMU can read them. No-op in bind mode."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext

_VOLUME_MOUNT = "/ksrc"
_OUT_MOUNT = "/out"
_BASE_IMAGE = "like_dbg_base"


def host_artifact_dir(workspace: Path, kernel_root: Path) -> Path:
    return workspace / "artifacts" / kernel_root.name


class ArtifactExporter:
    name = "export"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return ctx.host.storage_mode != "volume"

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_root is None or ctx.vmlinux is None or ctx.kernel_image is None:
            raise BuildError("missing build artifacts in context", remedy="run the Build stage first")
        out_dir = host_artifact_dir(self._workspace, ctx.kernel_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        rel_vmlinux = ctx.vmlinux.relative_to(_VOLUME_MOUNT)
        rel_image = ctx.kernel_image.relative_to(_VOLUME_MOUNT)
        volumes = {
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "ro"},
            str(out_dir): {"bind": _OUT_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"cp {_VOLUME_MOUNT}/{rel_vmlinux} {_OUT_MOUNT}/vmlinux")
            self._c.exec(container, f"cp {_VOLUME_MOUNT}/{rel_image} {_OUT_MOUNT}/Image")
        finally:
            self._c.stop(container)
        ctx.vmlinux = out_dir / "vmlinux"
        ctx.kernel_image = out_dir / "Image"
        return ctx
