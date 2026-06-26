"""Build stage: configure + compile the kernel in the kbuilder container."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.debug_profiles import parse_kernel_release
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


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
        chown_to: tuple[int, int] | None = None,
        patch_dirs: tuple[str, ...] = (),
    ) -> None:
        self._c = container
        self._recipe = recipe
        self._image = kbuilder_image
        self._workspace = workspace
        self._volume = kernel_volume
        self._chown_to = chown_to
        self._patch_dirs = patch_dirs

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
            logger.info(f"build cache hit: {label}")
            m = cache.load_manifest(self._workspace, "build", label)
            ctx.vmlinux = Path(m.paths["vmlinux_in_tree"])
            img = m.paths["image_host"] if m.storage_mode != "volume" else m.paths["image_in_tree"]
            ctx.kernel_image = Path(img)
            return ctx
        env = self._recipe.env()
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
        root = loc.kernel_root
        container = self._c.run_detached(self._image, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, make_command(env, "mrproper"), workdir=root)
            # Apply patches against the unpacked source tree (TOML list order; files sorted).
            for rel in self._patch_dirs:
                pdir = self._workspace / rel
                for pf in sorted(p for p in pdir.rglob("*") if p.is_file() and p.suffix in {".patch", ".diff"}):
                    container_patch = f"{_MOUNT}/{pf.relative_to(self._workspace).as_posix()}"
                    self._c.exec(container, f"patch -p1 -i {container_patch}", workdir=root)
            self._c.exec(container, make_command(env, "defconfig"), workdir=root)
            if self._recipe.fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._recipe.fragments)
                self._c.exec(
                    container,
                    f"./scripts/kconfig/merge_config.sh -m .config {frags} && {make_command(env, 'olddefconfig')}",
                    workdir=root,
                )
            self._c.exec(container, make_command(env, "all"), workdir=root)
            if self._chown_to is not None and ctx.host.storage_mode != "volume":
                uid, gid = self._chown_to
                self._c.exec(container, f"chown -R {uid}:{gid} {VOLUME_MOUNT}/{label}", workdir=root)
            release_text = self._c.exec(container, f"sed -n '1,6p' {root}/Makefile", workdir=root).output
            kernel_release = parse_kernel_release(release_text)
            export_dir = self._workspace / "artifacts" / label
            export_dir.mkdir(parents=True, exist_ok=True)
            config_host = export_dir / "config"
            config_text = self._c.exec(container, f"cat {root}/.config", workdir=root).output
            config_host.write_text(config_text)
        finally:
            self._c.stop(container)
        ctx.vmlinux = Path(loc.vmlinux_in_tree)
        ctx.kernel_image = Path(loc.image_host if ctx.host.storage_mode != "volume" else loc.image_in_tree)
        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="build",
                label=label,
                key=self._recipe.key,
                version=self._recipe.version,
                arch=self._recipe.arch,
                kernel_release=kernel_release,
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
                    "config_host": str(config_host),
                },
            ),
        )
        return ctx
