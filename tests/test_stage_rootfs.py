from pathlib import Path
from types import SimpleNamespace

import pytest

from likedbg.cache import Manifest
from likedbg.cache import RootfsRecipe
from likedbg.cache import manifest_exists
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
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
    from likedbg.config import GeneralCfg

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
    out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert c.run_kwargs["privileged"] is True
    assert out.rootfs_image == tmp_path / "artifacts" / "rootfs" / f"{_rrecipe().label}.img"


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
    out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert out.rootfs_image == img
    assert c.run_kwargs is None


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
    out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
    assert out.rootfs_image == tmp_path / "artifacts" / "rootfs" / f"{_rrecipe().label}.img"
    assert manifest_exists(tmp_path, "rootfs", _rrecipe().label) is True
    assert c.run_kwargs["privileged"] is True
