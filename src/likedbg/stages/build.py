"""Build stage: configure + compile the kernel in the kbuilder container."""

from __future__ import annotations

from pathlib import Path

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"
_VOLUME_MOUNT = "/ksrc"


def make_command(env: dict[str, str], target: str) -> str:
    parts = ["make", *[f"{k}={v}" for k, v in env.items()], "-j$(nproc)", target]
    return " ".join(parts)


class BuildStage:
    name = "build"

    def __init__(
        self,
        container: ContainerService,
        *,
        recipe: BuildRecipe,
        kbuilder_image: str,
        workspace: Path,
        kernel_volume: str,
    ) -> None:
        self._c = container
        self._recipe = recipe
        self._image = kbuilder_image
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None:
            raise BuildError("no build label in context", remedy="the CLI must set ctx.build_label")
        label = ctx.build_label
        loc = cache.locations(
            label,
            arch=self._recipe.arch,
            storage_mode=ctx.host.storage_mode,
            workspace=self._workspace,
            volume=self._volume,
        )
        if cache.manifest_exists(self._workspace, "build", label):
            m = cache.load_manifest(self._workspace, "build", label)
            ctx.vmlinux = Path(m.paths["vmlinux_in_tree"])
            ctx.kernel_image = Path(m.paths["image_in_tree"])
            return ctx
        env = self._recipe.env()
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
        }
        root = loc.kernel_root
        container = self._c.run_detached(self._image, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, make_command(env, "mrproper"), workdir=root)
            self._c.exec(container, make_command(env, "defconfig"), workdir=root)
            if self._recipe.fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._recipe.fragments)
                self._c.exec(
                    container,
                    f"./scripts/kconfig/merge_config.sh -m .config {frags} && {make_command(env, 'olddefconfig')}",
                    workdir=root,
                )
            self._c.exec(container, make_command(env, "all"), workdir=root)
        finally:
            self._c.stop(container)
        ctx.vmlinux = Path(loc.vmlinux_in_tree)
        ctx.kernel_image = Path(loc.image_in_tree)
        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="build",
                label=label,
                key=self._recipe.key,
                version=self._recipe.version,
                arch=self._recipe.arch,
                storage_mode=ctx.host.storage_mode,
                inputs=self._recipe.cache_inputs(),
                paths={
                    "kernel_root": loc.kernel_root,
                    "vmlinux_in_tree": loc.vmlinux_in_tree,
                    "image_in_tree": loc.image_in_tree,
                    "image_host": loc.image_host,
                    "gdb_mount_source": loc.gdb_mount_source,
                    "gdb_mount_type": loc.gdb_mount_type,
                    "gdb_vmlinux": loc.gdb_vmlinux,
                },
            ),
        )
        return ctx
