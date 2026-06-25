from pathlib import Path
from types import SimpleNamespace

import pytest
from loguru import logger

from likedbg.cache import Manifest
from likedbg.cache import RootfsRecipe
from likedbg.cache import manifest_exists
from likedbg.cache import write_manifest
from likedbg.config import GeneralCfg
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import RootfsError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.rootfs import rootfs_target


class FakeC(ContainerService):
    def __init__(self):
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1", logs=lambda **k: iter([b"building\n"]))

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _rrecipe():
    return RootfsRecipe(arch="arm64", distribution="bookworm", hostname="LIKE-DBG")


def _ctx(tmp_path):
    settings = Settings(general=GeneralCfg(arch="arm64"))
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="x",
        ssh_addr="x",
    )
    ctx = PipelineContext(settings=settings, host=host)
    ctx.rootfs_label = _rrecipe().label
    return ctx


def test_rootfs_target_path():
    assert rootfs_target(Path("/ws"), "rootfs-arm64-bookworm-deadbeef") == Path(
        "/ws/artifacts/rootfs/rootfs-arm64-bookworm-deadbeef.img"
    )


def test_run_starts_privileged_container_and_sets_rootfs(tmp_path):
    c = FakeC()
    ctx = _ctx(tmp_path)
    # Simulate the build container producing the image (FakeC runs no real container).
    target = rootfs_target(tmp_path, _rrecipe().label)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"img")
    out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert c.run_kwargs["privileged"] is True
    assert out.rootfs_image == target


def test_rootfs_reuses_present_image_without_rebuild(tmp_path):
    label = _rrecipe().label
    img = tmp_path / "artifacts" / "rootfs" / f"{label}.img"
    img.parent.mkdir(parents=True, exist_ok=True)
    img.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key=_rrecipe().key,
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(img)},
        ),
    )
    c = FakeC()
    ctx = _ctx(tmp_path)
    ctx.rootfs_label = label
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert out.rootfs_image == img
    assert c.run_kwargs is None
    assert any(f"rootfs cache hit: {label}" in m for m in msgs)


def test_rootfs_reuse_missing_image_raises(tmp_path):
    label = _rrecipe().label
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(tmp_path / "gone.img")},
        ),
    )
    ctx = _ctx(tmp_path)
    ctx.rootfs_label = label
    with pytest.raises(CacheError):
        RootfsStage(FakeC(), recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)


def test_rootfs_builds_and_writes_manifest_on_miss(tmp_path):
    c = FakeC()
    ctx = _ctx(tmp_path)
    ctx.rootfs_label = _rrecipe().label
    # Simulate the build container producing the image (FakeC runs no real container).
    target = rootfs_target(tmp_path, _rrecipe().label)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"img")
    out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert out.rootfs_image == target
    assert manifest_exists(tmp_path, "rootfs", _rrecipe().label) is True
    assert c.run_kwargs["privileged"] is True


def test_rootfs_build_without_image_raises_and_writes_no_manifest(tmp_path):
    # If the build container exits without producing the image, fail loudly — never write a
    # manifest claiming a cached rootfs that does not exist (the live-gate bug).
    c = FakeC()
    ctx = _ctx(tmp_path)
    ctx.rootfs_label = _rrecipe().label
    with pytest.raises(RootfsError):
        RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert manifest_exists(tmp_path, "rootfs", _rrecipe().label) is False


def test_rootfs_routes_container_logs_to_logger(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="DEBUG", format="{message}")
    try:
        c = FakeC()
        ctx = _ctx(tmp_path)
        rootfs_target(tmp_path, _rrecipe().label).parent.mkdir(parents=True, exist_ok=True)
        rootfs_target(tmp_path, _rrecipe().label).write_bytes(b"img")
        RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert any("building" in m for m in msgs)  # FakeC.logs yields b"building\n"


class _RetryFakeC(FakeC):
    """Produces the image only on the SECOND build attempt (simulates the first-run transient)."""

    def __init__(self, target: Path):
        super().__init__()
        self._target = target
        self.attempts = 0

    def run_detached(self, image, **kwargs):
        self.attempts += 1
        if self.attempts == 2:
            self._target.parent.mkdir(parents=True, exist_ok=True)
            self._target.write_bytes(b"img")
        return super().run_detached(image, **kwargs)


def test_rootfs_retries_once_on_missing_image_then_succeeds(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="WARNING", format="{message}")
    try:
        target = rootfs_target(tmp_path, _rrecipe().label)
        c = _RetryFakeC(target)
        ctx = _ctx(tmp_path)
        out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert c.attempts == 2 and out.rootfs_image == target
    assert any("retry" in m.lower() for m in msgs)
    assert any(str(target) in m for m in msgs)


def test_rootfs_exception_is_not_retried(tmp_path):
    class _BoomC(FakeC):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def run_detached(self, image, **kwargs):
            self.attempts += 1
            raise RuntimeError("docker down")

    c = _BoomC()
    ctx = _ctx(tmp_path)
    with pytest.raises(RootfsError):  # run_detached failure is wrapped, propagates without retry
        RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert c.attempts == 1
