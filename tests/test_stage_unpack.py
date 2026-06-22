from types import SimpleNamespace

import pytest

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import UnpackError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.unpack import UnpackStage


class FakeContainerService(ContainerService):
    def __init__(self):
        self.execs = []
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(storage_mode, tmp_path):
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode=storage_mode,
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = tmp_path / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    return ctx


def test_volume_mode_mounts_named_volume(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert "likedbg_ksrc" in mounts


def test_extract_command_issued_and_kernel_root_set(tmp_path):
    svc = FakeContainerService()
    out = UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    assert any("tar" in c for c in svc.execs)
    assert out.kernel_root is not None and "linux-6.6" in str(out.kernel_root)


def test_archive_outside_workspace_raises_unpack_error(tmp_path):
    """Archive not under workspace should raise UnpackError with an actionable remedy."""
    ws = tmp_path / "ws"
    ws.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="bind",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = elsewhere / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    with pytest.raises(UnpackError, match="not under the workspace"):
        UnpackStage(FakeContainerService(), kernel_volume="likedbg_ksrc", workspace=ws).run(ctx)
