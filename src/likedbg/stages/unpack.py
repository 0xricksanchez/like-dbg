"""Unpack stage: source setup. Materializes the SHARED source tree at
/ksrc/src/<src_label>, in-container: tar-extracts the archive, applies patches, `mrproper`s,
and locks the tree read-only (`chmod -R a-w`) so every build sharing this src_label builds
against byte-identical, tamper-evident sources. Content-addressed by src_key (ADR pending):
independent of arch/compiler/make_vars, so many builds of the same (version, patches) share
one source tree."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.constants import BASE_IMAGE
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.errors import UnpackError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


class UnpackStage:
    name = "unpack"

    def __init__(
        self,
        container: ContainerService,
        *,
        recipe: BuildRecipe,
        kernel_volume: str,
        workspace: Path,
        patch_dirs: tuple[str, ...] = (),
    ) -> None:
        self._c = container
        self._recipe = recipe
        self._volume = kernel_volume
        self._workspace = workspace
        self._patch_dirs = patch_dirs

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        recipe = self._recipe
        loc = cache.locations(
            recipe.label,
            arch=recipe.arch,
            storage_mode=ctx.host.storage_mode,
            workspace=self._workspace,
            volume=self._volume,
            src_label=recipe.src_label,
        )
        ctx.source_root = Path(loc.source_root)
        ctx.srckey = recipe.src_key
        ctx.objdir = Path(loc.objdir)
        ctx.kernel_root = Path(loc.kernel_root)  # deprecated alias, kept for compat (Task 12 removes it)

        if cache.manifest_exists(self._workspace, "source", recipe.src_label):
            logger.info(f"unpack cache hit: {recipe.src_label}")
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
        source_root = loc.source_root
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"mkdir -p {source_root}")
            self._c.exec(container, f"tar -C {source_root} --strip-components=1 -xf {archive_in}")
            # Apply patches against the freshly unpacked source tree (TOML list order; files sorted).
            for rel_dir in self._patch_dirs:
                pdir = self._workspace / rel_dir
                for pf in sorted(p for p in pdir.rglob("*") if p.is_file() and p.suffix in {".patch", ".diff"}):
                    container_patch = f"{_MOUNT}/{pf.relative_to(self._workspace).as_posix()}"
                    self._c.exec(container, f"patch -p1 -i {container_patch}", workdir=source_root)
            make_vars = " ".join(f"{k}={v}" for k, v in recipe.make_vars)
            self._c.exec(container, f"make {make_vars} -C {source_root} mrproper")
            self._c.exec(container, f"chmod -R a-w {source_root}")
        finally:
            self._c.stop(container)

        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="source",
                label=recipe.src_label,
                key=recipe.src_key,
                version=recipe.version,
                arch="",
                inputs={f"patch:{name}": h for name, h in recipe.patch_hashes},
            ),
        )
        return ctx
