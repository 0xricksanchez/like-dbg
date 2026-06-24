"""Unpack stage: extract the kernel archive into case-safe storage, in-container."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg.constants import BASE_IMAGE
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.errors import UnpackError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


class UnpackStage:
    name = "unpack"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None:
            raise UnpackError("no build label in context", remedy="the CLI must set ctx.build_label")
        label = ctx.build_label
        if cache.manifest_exists(self._workspace, "build", label):
            logger.info(f"unpack cache hit: {label}")
            ctx.kernel_root = Path(f"{VOLUME_MOUNT}/{label}")
            return ctx
        if ctx.kernel_archive is None:
            raise UnpackError(
                "no kernel archive in context",
                remedy="run the Download stage first",
            )
        try:
            rel = ctx.kernel_archive.relative_to(self._workspace)
        except ValueError as exc:
            raise UnpackError(
                f"kernel archive {ctx.kernel_archive} is not under the workspace {self._workspace}",
                remedy="configure the Download stage's dl_dir to a subdirectory of the workspace so the unpack container can read it at /io",
            ) from exc
        archive_in = f"{_MOUNT}/{rel}"
        keyed = f"{VOLUME_MOUNT}/{label}"
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"rm -rf {keyed}")
            self._c.exec(container, f"mkdir -p {keyed}")
            self._c.exec(container, f"tar -C {keyed} --strip-components=1 -xf {archive_in}")
        finally:
            self._c.stop(container)
        ctx.kernel_root = Path(keyed)
        return ctx
