"""Rootfs stage: build a native-arch root filesystem image via rootfs.sh in a
privileged container, record its host path, and write a rootfs Manifest."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg import images
from likedbg.cache import RootfsRecipe
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import RootfsError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


def rootfs_target(workspace: Path, label: str) -> Path:
    return workspace / "artifacts" / "rootfs" / f"{label}.img"


class RootfsStage:
    name = "rootfs"

    def __init__(
        self, container: ContainerService, *, recipe: RootfsRecipe, rootfs_image: str, workspace: Path
    ) -> None:
        self._c = container
        self._recipe = recipe
        self._image = rootfs_image
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        # Never skip: a cached image still has to be recorded in the context so the
        # Debuggee stage can attach it as the root disk. run() is idempotent — it
        # records the path and only rebuilds when the manifest is missing.
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.rootfs_label is None:
            raise RootfsError("no rootfs label in context", remedy="the CLI must set ctx.rootfs_label")
        label = ctx.rootfs_label
        target = rootfs_target(self._workspace, label)

        if cache.manifest_exists(self._workspace, "rootfs", label):
            logger.info(f"rootfs cache hit: {label}")
            m = cache.load_manifest(self._workspace, "rootfs", label)
            img = Path(m.paths["image_host"])
            if not img.exists():
                raise CacheError(
                    f"cached rootfs {label} image is gone",
                    remedy=f"`start_kgdb --clean {label}` and rebuild",
                )
            ctx.rootfs_image = img
            return ctx

        self._require_current_rootfs_image()
        if not self._attempt(target):
            logger.warning(f"rootfs build did not produce {target}; retrying once...")
            if not self._attempt(target):
                raise RootfsError(
                    f"rootfs build did not produce {target}",
                    remedy="see artifacts/logs/latest.log (rootfs.sh output); the container exited without writing the image",
                )
        ctx.rootfs_image = target
        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="rootfs",
                label=label,
                key=self._recipe.key,
                version="",
                arch=self._recipe.arch,
                storage_mode=ctx.host.storage_mode,
                inputs=self._recipe.cache_inputs(),
                paths={
                    "image_host": str(target),
                    "ssh_key": str(target.parent / f"{target.name}.id_ed25519"),
                },
            ),
        )
        return ctx

    def _require_current_rootfs_image(self) -> None:
        spec = next((s for s in images.IMAGES if s.tag == self._image), None)
        if spec is None:
            return
        try:
            wanted = images.input_sha(spec, self._workspace)
        except FileNotFoundError:
            # Unit tests often use temp workspaces that are not full repo checkouts.
            return
        try:
            actual = self._c.image_labels(self._image).get(images.LABEL)
        except Exception as exc:  # noqa: BLE001
            raise RootfsError(
                f"failed to inspect rootfs image {self._image}",
                remedy="run `uv run ./start_kgdb --build-images`",
            ) from exc
        if actual != wanted:
            raise RootfsError(
                f"rootfs image {self._image} is stale",
                remedy="run `uv run ./start_kgdb --build-images` before rebuilding rootfs",
            )

    def _attempt(self, target: Path) -> bool:
        target.parent.mkdir(parents=True, exist_ok=True)
        qemu_arch = "aarch64" if self._recipe.arch == "arm64" else "x86_64"
        cmd = (
            f"/bin/bash -lc '. /home/user/rootfs.sh -n {target.name} -a {qemu_arch} "
            f"-d {self._recipe.distribution} -u user -h {self._recipe.hostname}'"
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
            logger.debug(line.decode(errors="replace").rstrip() if isinstance(line, bytes) else str(line).rstrip())
        self._c.stop(container)
        return target.exists()
