"""Build stage: configure + compile the kernel in the kbuilder container."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext
from likedbg.toolchain import resolve_toolchain

_MOUNT = "/io"
_VOLUME_MOUNT = "/ksrc"


def make_command(env: dict[str, str], target: str) -> str:
    vars_str = " ".join(f"{k}={v}" for k, v in env.items())
    return f"make {vars_str} -j$(nproc) {target}".replace("  ", " ").strip()


def _image_path(kernel_root: Path, arch: str) -> Path:
    name = "bzImage" if arch == "x86_64" else "Image"
    return kernel_root / "arch" / arch / "boot" / name


class BuildStage:
    name = "build"

    def __init__(
        self,
        container: ContainerService,
        *,
        kbuilder_image: str,
        fragments: list[str],
        workspace: Path,
        kernel_volume: str,
    ) -> None:
        self._c = container
        self._image = kbuilder_image
        self._fragments = fragments
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def _volumes(self, ctx: PipelineContext) -> dict[str, dict[str, str]]:
        # Mount the workspace at /io (for the kconfig fragments) and, in volume mode,
        # the named kernel-source volume at /ksrc (where Unpack put the tree).
        if ctx.host.storage_mode == "volume":
            return {
                str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
                self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
            }
        return {str(self._workspace): {"bind": _MOUNT, "mode": "rw"}}

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_root is None:
            raise BuildError("no kernel_root in context", remedy="run the Unpack stage first")
        arch = ctx.settings.general.arch
        env = resolve_toolchain(ctx.settings.kernel_builder.compiler, arch).make_vars
        root = ctx.kernel_root
        container = self._c.run_detached(self._image, volumes=self._volumes(ctx), detach=True, tty=True)
        try:
            self._c.exec(container, make_command(env, "mrproper"), workdir=str(root))
            self._c.exec(container, make_command(env, "defconfig"), workdir=str(root))
            if self._fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._fragments)
                self._c.exec(
                    container,
                    f"./scripts/kconfig/merge_config.sh -m .config {frags} && {make_command(env, 'olddefconfig')}",
                    workdir=str(root),
                )
            self._c.exec(container, make_command(env, "all"), workdir=str(root))
        finally:
            self._c.stop(container)
        ctx.vmlinux = root / "vmlinux"
        ctx.kernel_image = _image_path(root, arch)
        return ctx
