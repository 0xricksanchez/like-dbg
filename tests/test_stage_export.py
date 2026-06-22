from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.export import ArtifactExporter


class FakeC(ContainerService):
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


def _ctx(storage, tmp_path):
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode=storage,
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_root = Path("/ksrc/linux-6.6.30")
    ctx.vmlinux = Path("/ksrc/linux-6.6.30/vmlinux")
    ctx.kernel_image = Path("/ksrc/linux-6.6.30/arch/arm64/boot/Image")
    return ctx


def test_skips_in_bind_mode(tmp_path):
    assert ArtifactExporter(FakeC(), kernel_volume="v", workspace=tmp_path).should_skip(_ctx("bind", tmp_path)) is True


def test_volume_mode_copies_and_rewrites_paths(tmp_path):
    c = FakeC()
    out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    assert any("cp" in cmd for cmd in c.execs)
    assert "likedbg_ksrc" in str(c.run_kwargs["volumes"])
    assert out.kernel_image == tmp_path / "artifacts" / "linux-6.6.30" / "Image"
    assert out.vmlinux == tmp_path / "artifacts" / "linux-6.6.30" / "vmlinux"
