"""CacheEvictionStage: opt-in auto-sweep gating (should_skip) + the 90% low-water prune call."""

from types import SimpleNamespace

import likedbg.stages.cache_eviction as cache_eviction
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.cache_eviction import CacheEvictionStage

G = 1024**3


class FakeC(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(*, build_label="current-build", build_was_cached=False):
    s = Settings.model_validate({"general": {"arch": "arm64"}})
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
    )
    ctx = PipelineContext(settings=s, host=host, build_label=build_label)
    ctx.build_was_cached = build_was_cached
    return ctx


def test_should_skip_true_when_max_size_unset(tmp_path):
    stage = CacheEvictionStage(FakeC(), workspace=tmp_path, max_size="")
    assert stage.should_skip(_ctx(build_was_cached=False)) is True


def test_should_skip_true_when_build_was_cached_even_if_armed(tmp_path):
    stage = CacheEvictionStage(FakeC(), workspace=tmp_path, max_size="20G")
    assert stage.should_skip(_ctx(build_was_cached=True)) is True


def test_should_skip_false_when_armed_and_fresh_build(tmp_path):
    stage = CacheEvictionStage(FakeC(), workspace=tmp_path, max_size="20G")
    assert stage.should_skip(_ctx(build_was_cached=False)) is False


def test_run_prunes_to_90_percent_low_water_and_protects_current_build(tmp_path, monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_prune_cache(container, workspace, target_bytes, *, protect, volume):
        calls.append({"target": target_bytes, "protect": protect, "volume": volume})
        return ["evicted-x"]

    monkeypatch.setattr(cache_eviction.cache, "prune_cache", fake_prune_cache)

    stage = CacheEvictionStage(FakeC(), workspace=tmp_path, max_size="10G", volume="likedbg_ksrc")
    ctx = _ctx(build_label="current-build", build_was_cached=False)
    out = stage.run(ctx)

    assert out is ctx
    assert calls == [
        {"target": int(0.9 * 10 * G), "protect": {"current-build"}, "volume": "likedbg_ksrc"}
    ]


def test_run_falls_back_to_empty_protect_when_no_build_label(tmp_path, monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_prune_cache(container, workspace, target_bytes, *, protect, volume):
        calls.append({"protect": protect})
        return []

    monkeypatch.setattr(cache_eviction.cache, "prune_cache", fake_prune_cache)

    stage = CacheEvictionStage(FakeC(), workspace=tmp_path, max_size="10G")
    ctx = _ctx(build_label=None, build_was_cached=False)
    stage.run(ctx)

    assert calls == [{"protect": set()}]
