"""Build stage: configure + compile the kernel in the kbuilder container.

Builds out-of-tree (`make -C <source_root> O=<objdir>`) against the shared, read-only source
tree that UnpackStage materialized (already patched and mrproper'd once for every build sharing
that src_label). BuildStage itself no longer applies patches or runs mrproper."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.constants import LIKEDBG_CCACHE_VOLUME
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.debug_profiles import parse_kernel_release
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


def make_command(env: dict[str, str], target: str, *, source_root: str = "", objdir: str = "") -> str:
    parts = ["make", *[f"{k}={v}" for k, v in env.items()]]
    if source_root and objdir:
        parts += ["-C", source_root, f"O={objdir}"]
    parts += ["-j$(nproc)", target]
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
        ccache: bool = False,
        ccache_max_size: str = "5G",
    ) -> None:
        self._c = container
        self._recipe = recipe
        self._image = kbuilder_image
        self._workspace = workspace
        self._volume = kernel_volume
        self._chown_to = chown_to
        self._ccache = ccache
        self._ccache_max_size = ccache_max_size

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def _ccache_env_prefix(self) -> str:
        """Shell env prefix for ccache-enabled make invocations.

        ContainerService.exec has no env param, so these are inlined into the command string.
        CCACHE_NOHASHDIR=1 is required: without it, ccache keys on the (per-build) objdir path
        baked into compiler -g debug info, defeating cross-config cache hits. Deliberately does
        NOT set -fdebug-prefix-map/-ffile-prefix-map (out of scope for this task).
        """
        if not self._ccache:
            return ""
        return f"CCACHE_DIR=/ccache CCACHE_NOHASHDIR=1 CCACHE_MAXSIZE={self._ccache_max_size} "

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
            src_label=self._recipe.src_label,
        )
        source_root = loc.source_root
        objdir = loc.objdir
        if cache.manifest_exists(self._workspace, "build", label):
            logger.info(f"build cache hit: {label}")
            m = cache.load_manifest(self._workspace, "build", label)
            ctx.vmlinux = Path(m.paths["vmlinux_in_tree"])
            img = m.paths["image_host"] if m.storage_mode != "volume" else m.paths["image_in_tree"]
            ctx.kernel_image = Path(img)
            ctx.objdir = Path(objdir)
            ctx.kernel_root = Path(objdir)  # deprecated alias, kept for compat
            return ctx
        env = self._recipe.env()
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
        if self._ccache:
            volumes[LIKEDBG_CCACHE_VOLUME] = {"bind": "/ccache", "mode": "rw"}
        container = self._c.run_detached(self._image, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"mkdir -p {objdir}")
            ccache_env = self._ccache_env_prefix()
            # Out-of-tree build against the shared, read-only source (mrproper + patches already
            # applied once in UnpackStage): make -C <source_root> O=<objdir> ...
            self._c.exec(
                container,
                ccache_env + make_command(env, "defconfig", source_root=source_root, objdir=objdir),
                workdir=source_root,
            )
            if self._recipe.fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._recipe.fragments)
                # -O <objdir> is the standard out-of-tree merge_config.sh form; if a live-gate on
                # 6.6.30 shows it misbehaving, fall back to workdir=<objdir> invoking
                # <source_root>/scripts/kconfig/merge_config.sh instead.
                merge_cmd = f"./scripts/kconfig/merge_config.sh -m -O {objdir} {objdir}/.config {frags}"
                olddefconfig_cmd = make_command(env, "olddefconfig", source_root=source_root, objdir=objdir)
                self._c.exec(container, f"{ccache_env}{merge_cmd} && {olddefconfig_cmd}", workdir=source_root)
            compile_cmd = make_command(env, "all", source_root=source_root, objdir=objdir)
            if self._ccache and self._recipe.compiler == "clang":
                # CC="ccache <compiler>" appended (not merged into `env`) so the shell keeps
                # "ccache <compiler>" as a single quoted CC value; GNU make accepts VAR=value
                # overrides anywhere on the command line, including after the target.
                # gcc/other-compiler ccache wiring uses the CROSS_COMPILE-derived CC and is deferred
                # until a gcc build path is actually wired (the kbuilder image has no gcc today).
                compile_cmd = f'{compile_cmd} CC="ccache {self._recipe.compiler}"'
            self._c.exec(container, ccache_env + compile_cmd, workdir=source_root)
            if self._chown_to is not None and ctx.host.storage_mode != "volume":
                uid, gid = self._chown_to
                self._c.exec(container, f"chown -R {uid}:{gid} {objdir}")
            release_text = self._c.exec(container, f"sed -n '1,6p' {source_root}/Makefile").output
            kernel_release = parse_kernel_release(release_text)
            export_dir = self._workspace / "artifacts" / label
            export_dir.mkdir(parents=True, exist_ok=True)
            config_host = export_dir / "config"
            # Strip CRLF from the tty-backed container read so the stored snapshot is clean LF.
            # make O=<objdir> writes .config into the objdir, not the (read-only) source tree.
            config_text = self._c.exec(container, f"cat {objdir}/.config").output.replace("\r\n", "\n")
            config_host.write_text(config_text)
        finally:
            self._c.stop(container)
        ctx.vmlinux = Path(loc.vmlinux_in_tree)
        ctx.kernel_image = Path(loc.image_host if ctx.host.storage_mode != "volume" else loc.image_in_tree)
        ctx.objdir = Path(objdir)
        ctx.kernel_root = Path(objdir)  # deprecated alias, kept for compat
        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="build",
                label=label,
                key=self._recipe.key,
                version=self._recipe.version,
                arch=self._recipe.arch,
                srckey=self._recipe.src_key,
                kernel_release=kernel_release,
                storage_mode=ctx.host.storage_mode,
                inputs=self._recipe.cache_inputs(),
                paths={
                    "kernel_root": loc.kernel_root,
                    "objdir": objdir,
                    "source_root": source_root,
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
