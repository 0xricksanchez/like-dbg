"""Boot-time stage: build each build.custom_modules entry out-of-tree against the built kernel tree and
stage the .ko into the Guest share (exploit/modules/), so --insmod can load it live."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from likedbg import cache
from likedbg.constants import KERNEL_VOLUME
from likedbg.errors import BuildError
from likedbg.modules import stage_module
from likedbg.pipeline import PipelineContext


class ModuleBuildStage:
    name = "module-build"

    def __init__(
        self,
        container: Any,
        *,
        image: str,
        workspace: Path,
        env: dict[str, str],
        arch: str,
        volume: str = KERNEL_VOLUME,
    ) -> None:
        self._c = container
        self._image = image
        self._workspace = workspace
        self._env = env
        self._arch = arch
        self._volume = volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return not ctx.settings.build.custom_modules

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None:
            raise BuildError("no build label in context", remedy="run the Build stage first")
        loc = cache.locations(
            ctx.build_label,
            arch=self._arch,
            storage_mode=ctx.host.storage_mode,
            workspace=self._workspace,
            volume=self._volume,
        )
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        out_dir = self._workspace / eff.share_dir / "modules"
        for rel in ctx.settings.build.custom_modules:
            stage_module(
                self._c,
                entry=self._workspace / rel,
                out_dir=out_dir,
                # loc.objdir is the KBUILD dir for an O=-built kernel (carries a `source` symlink
                # into the tree mounted below). See modules.py.
                kernel_root=loc.objdir,
                # ksrc root mounted ro: exposes both obj/<label> and src/<src_label> under it.
                mount_source=loc.gdb_mount_source,
                env=self._env,
                image=self._image,
                volume=self._volume,
                kernel_label=ctx.build_label,
            )
        return ctx
