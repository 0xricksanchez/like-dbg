"""CacheEvictionStage: opt-in auto-sweep after a NEW build. Keeps [cache] max_size honored
without a separate cron/manual step: once a fresh build lands (BuildStage cache-miss), evict
the LRU cache down to a 90% low-water mark so the next build doesn't immediately re-trip the
cap. A no-op unless [cache] max_size is set, and skipped entirely on a cache hit (no disk added).
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg.constants import KERNEL_VOLUME
from likedbg.container_service import ContainerService
from likedbg.pipeline import PipelineContext

_LOW_WATER = 0.9


class CacheEvictionStage:
    name = "cache-eviction"

    def __init__(
        self,
        container: ContainerService,
        *,
        workspace: Path,
        max_size: str,
        volume: str = KERNEL_VOLUME,
    ) -> None:
        self._c = container
        self._workspace = workspace
        self._max_size = max_size
        self._volume = volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        # unset max_size (default) -> no cap to enforce; cache hit -> no disk added, nothing to sweep.
        return cache.parse_size(self._max_size) <= 0 or ctx.build_was_cached

    def run(self, ctx: PipelineContext) -> PipelineContext:
        target = int(_LOW_WATER * cache.parse_size(self._max_size))
        protect = {ctx.build_label} if ctx.build_label is not None else set()
        evicted = cache.prune_cache(self._c, self._workspace, target, protect=protect, volume=self._volume)
        if evicted:
            logger.info(f"auto-sweep evicted: {', '.join(evicted)}")
        else:
            logger.debug("auto-sweep: nothing to prune")
        return ctx
