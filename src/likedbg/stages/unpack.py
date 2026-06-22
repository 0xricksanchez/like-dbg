"""Unpack stage: extract the kernel archive into case-safe storage, in-container."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"
_VOLUME_MOUNT = "/ksrc"
_BASE_IMAGE = "like_dbg_base"


def _archive_stem(archive: Path) -> str:
    # linux-6.6.tar.gz -> linux-6.6
    return archive.name.split(".tar.")[0]


def kernel_root_path(ctx: PipelineContext, *, mount: str) -> Path:
    assert ctx.kernel_archive is not None
    return Path(mount) / _archive_stem(ctx.kernel_archive)


class UnpackStage:
    name = "unpack"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.kernel_archive is not None
        volume_mode = ctx.host.storage_mode == "volume"
        mount = _VOLUME_MOUNT if volume_mode else _MOUNT
        if volume_mode:
            volumes = {
                str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
                self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
            }
            archive_in = f"{_MOUNT}/{ctx.kernel_archive.relative_to(self._workspace)}"
        else:
            volumes = {str(self._workspace): {"bind": _MOUNT, "mode": "rw"}}
            archive_in = f"{_MOUNT}/{ctx.kernel_archive.relative_to(self._workspace)}"
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"mkdir -p {mount}")
            self._c.exec(container, f"tar -C {mount} -xf {archive_in}")
        finally:
            self._c.stop(container)
        ctx.kernel_root = kernel_root_path(ctx, mount=mount)
        return ctx
