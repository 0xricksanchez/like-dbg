from pathlib import Path
from types import SimpleNamespace

from loguru import logger

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import ContainerError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.export import ArtifactExporter

_LABEL = "linux-6.6.30-a1b2c3d4"


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []
        self.run_kwargs: dict | None = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


class FailingExecFakeC(FakeC):
    """FakeC whose exec raises ContainerError on the first test -e call."""

    def exec(self, container, cmd, *, workdir=None):
        if cmd.startswith("test -e"):
            raise ContainerError("artifact missing")
        return super().exec(container, cmd, workdir=workdir)


def _ctx(storage: str, tmp_path: Path) -> PipelineContext:
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode=storage,
        gdbstub_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.build_label = _LABEL
    ctx.kernel_root = Path(f"/ksrc/{_LABEL}")
    ctx.vmlinux = Path(f"/ksrc/{_LABEL}/vmlinux")
    ctx.kernel_image = Path(f"/ksrc/{_LABEL}/arch/arm64/boot/Image")
    return ctx


def test_skips_in_bind_mode(tmp_path):
    assert ArtifactExporter(FakeC(), kernel_volume="v", workspace=tmp_path).should_skip(_ctx("bind", tmp_path)) is True


def test_volume_mode_copies_and_rewrites_paths(tmp_path):
    c = FakeC()
    out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    # Image is exported to the host workspace for native QEMU, keyed by build_label.
    assert out.kernel_image == tmp_path / "artifacts" / _LABEL / "Image"
    assert "likedbg_ksrc" in str(c.run_kwargs["volumes"])
    # Both in-volume artifacts must be verified before copy.
    assert any(f"test -e /ksrc/{_LABEL}/vmlinux" in cmd for cmd in c.execs)
    assert any(f"test -e /ksrc/{_LABEL}/arch/arm64/boot/Image" in cmd for cmd in c.execs)
    assert any("cp" in cmd and "Image" in cmd for cmd in c.execs)
    # vmlinux stays in the volume so in-container gdb can read it (spec §4.6).
    assert out.vmlinux == Path(f"/ksrc/{_LABEL}/vmlinux")


def test_export_verifies_then_copies_and_sets_host_image(tmp_path):
    c = FakeC()
    ctx = _ctx("volume", tmp_path)
    out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
    assert out.kernel_image == tmp_path / "artifacts" / _LABEL / "Image"
    allcmds = " ; ".join(c.execs)
    assert f"test -e /ksrc/{_LABEL}/vmlinux" in allcmds
    assert f"cp /ksrc/{_LABEL}/arch/arm64/boot/Image" in allcmds


def test_export_idempotent_skip_when_host_image_exists(tmp_path):
    """If the host Image already exists, export skips the container run."""
    c = FakeC()
    ctx = _ctx("volume", tmp_path)
    host_image = tmp_path / "artifacts" / _LABEL / "Image"
    host_image.parent.mkdir(parents=True)
    host_image.write_bytes(b"fake")
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert out.kernel_image == host_image
    assert c.execs == []  # no container commands issued
    assert any(f"export cache hit: {host_image}" in m for m in msgs)


def test_export_cache_error_on_missing_artifact(tmp_path):
    """ContainerError from test -e is re-raised as CacheError with --clean remedy."""
    import pytest

    c = FailingExecFakeC()
    ctx = _ctx("volume", tmp_path)
    with pytest.raises(CacheError, match=r"--clean"):
        ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
