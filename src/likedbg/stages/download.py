"""Download stage: resolve a kernel version and fetch its source archive."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from likedbg.config import KernelDlCfg
from likedbg.errors import DownloadError
from likedbg.pipeline import PipelineContext

Fetcher = Callable[[str, Path], None]

_SNAPSHOT = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-"
_CDN = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/linux-{mmp}.tar.xz"


def resolve_version(cfg: KernelDlCfg) -> str:
    if cfg.mmp:
        return cfg.mmp
    if cfg.tag:
        return cfg.tag
    if cfg.commit:
        return cfg.commit
    raise DownloadError(
        "no kernel version specified",
        remedy="set [kernel_dl] mmp, tag, or commit in your .ini",
    )


def archive_url(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return _CDN.format(major=parts[0], mmp=version)
    return f"{_SNAPSHOT}{version}.tar.gz"


def _archive_name(version: str) -> str:
    return f"linux-{version}.tar.{'xz' if archive_url(version).endswith('xz') else 'gz'}"


class DownloadStage:
    name = "download"

    def __init__(self, fetcher: Fetcher, *, dl_dir: Path) -> None:
        self._fetch = fetcher
        self._dl_dir = dl_dir

    def _dest(self, ctx: PipelineContext) -> Path:
        return self._dl_dir / _archive_name(resolve_version(ctx.settings.kernel_dl))

    def should_skip(self, ctx: PipelineContext) -> bool:
        # Never skip: a cached archive still has to be recorded in the context for the
        # Unpack stage. run() is idempotent — it sets ctx.kernel_archive and only
        # fetches when the file is missing.
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        self._dl_dir.mkdir(parents=True, exist_ok=True)
        version = resolve_version(ctx.settings.kernel_dl)
        dest = self._dest(ctx)
        if not dest.exists():
            self._fetch(archive_url(version), dest)
        ctx.kernel_archive = dest
        return ctx
