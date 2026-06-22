"""Rootfs stage: build a native-arch root filesystem image via rootfs.sh in a
privileged container, and record its host path."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import RootfsError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


def rootfs_target(workspace: Path, arch: str) -> Path:
    return workspace / "artifacts" / f"rootfs-{arch}.img"


class RootfsStage:
    name = "rootfs"

    def __init__(self, container: ContainerService, *, rootfs_image: str, workspace: Path) -> None:
        self._c = container
        self._image = rootfs_image
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        # Never skip: a cached image still has to be recorded in the context so the
        # Debuggee stage can attach it as the root disk. run() is idempotent — it
        # records the path and only rebuilds when the image is missing.
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        arch = ctx.settings.general.arch
        target = rootfs_target(self._workspace, arch)
        if target.exists():
            ctx.rootfs_image = target
            return ctx
        target.parent.mkdir(parents=True, exist_ok=True)
        cfg = ctx.settings.rootfs
        qemu_arch = "aarch64" if arch == "arm64" else "x86_64"
        name = target.name
        cmd = (
            f"/bin/bash -lc '. /home/user/rootfs.sh -n {name} -a {qemu_arch} "
            f"-d {cfg.distribution} -u user -h {cfg.hostname}'"
        )
        try:
            container = self._c.run_detached(
                self._image,
                volumes={str(target.parent): {"bind": _MOUNT, "mode": "rw"}},
                privileged=True,
                detach=True,
                command=cmd,
            )
        except Exception as exc:  # noqa: BLE001
            raise RootfsError("failed to start rootfs build container", remedy="check the rootfs image exists") from exc
        for line in container.logs(stream=True, follow=True):
            _ = line
        self._c.stop(container)
        ctx.rootfs_image = target
        return ctx
