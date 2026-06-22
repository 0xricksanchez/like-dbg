from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
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
    return PipelineContext(settings=settings, host=host)


def test_rootfs_target_path():
    assert rootfs_target(Path("/ws"), "arm64") == Path("/ws/artifacts/rootfs-arm64.img")


def test_run_starts_privileged_container_and_sets_rootfs(tmp_path):
    c = FakeC()
    out = RootfsStage(c, rootfs_image="like_rootfs", workspace=tmp_path).run(_ctx(tmp_path))
    assert c.run_kwargs["privileged"] is True
    assert out.rootfs_image == tmp_path / "artifacts" / "rootfs-arm64.img"
