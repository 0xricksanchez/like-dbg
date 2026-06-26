from types import SimpleNamespace

import pytest
from loguru import logger

from likedbg.cache import Manifest
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import UnpackError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.unpack import UnpackStage

_LABEL = "linux-6.6-gef-a1b2c3d4"


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


def _ctx(storage_mode, tmp_path, *, label: str = _LABEL):
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode=storage_mode,
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = tmp_path / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    ctx.build_label = label
    return ctx


def test_volume_mode_mounts_named_volume(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert "likedbg_ksrc" in mounts


def test_extract_command_issued_and_kernel_root_set(tmp_path):
    svc = FakeContainerService()
    out = UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
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
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="bind",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = elsewhere / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    ctx.build_label = _LABEL
    with pytest.raises(UnpackError, match="not under the workspace"):
        UnpackStage(FakeContainerService(), kernel_volume="likedbg_ksrc", workspace=ws).run(ctx)


def test_unpack_reuses_when_manifest_present(tmp_path):
    label = "linux-6.6.30-gef-a1b2c3d4"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={"kernel_root": f"/ksrc/{label}"},
        ),
    )
    svc = FakeContainerService()
    ctx = _ctx("volume", tmp_path, label=label)
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        out = UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert str(out.kernel_root) == f"/ksrc/{label}"
    assert svc.run_kwargs is None  # no container started on reuse
    assert any(f"unpack cache hit: {label}" in m for m in msgs)


def test_unpack_wipes_then_extracts_on_miss(tmp_path):
    label = "linux-6.6.30-gef-a1b2c3d4"
    svc = FakeContainerService()
    ctx = _ctx("volume", tmp_path, label=label)
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
    joined = " ; ".join(svc.execs)
    assert f"rm -rf /ksrc/{label}" in joined
    assert f"tar -C /ksrc/{label} --strip-components=1" in joined


def test_bind_mode_mounts_host_ksrc_dir(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in mounts
    assert "likedbg_ksrc" not in mounts
    assert (tmp_path / "artifacts" / "ksrc").is_dir()  # bind source created
