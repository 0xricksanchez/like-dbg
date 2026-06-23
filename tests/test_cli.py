from types import SimpleNamespace

import pytest

from likedbg import cache
from likedbg.cache import Manifest
from likedbg.cache import build_recipe
from likedbg.cache import rootfs_recipe
from likedbg.cache import write_manifest
from likedbg.cli import build_pipeline
from likedbg.cli import cmd_clean
from likedbg.cli import require_volume_mode
from likedbg.cli import summarize_cache
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import HostCapabilityError
from likedbg.host_profile import HostProfile
from likedbg.session import Session


class _FakeContainer(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: None)
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        ext="gef",
        panes=(1, 2),
        build_recipe=br,
        rootfs_recipe=rr,
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]


def _host(mode):
    return HostProfile(
        os="linux",
        host_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=mode,
        gdbstub_addr="localhost",
        ssh_addr="localhost",
    )


def test_require_volume_mode_accepts_volume():
    require_volume_mode(_host("volume"))  # no raise


def test_require_volume_mode_rejects_bind():
    with pytest.raises(HostCapabilityError):
        require_volume_mode(_host("bind"))


def test_summarize_cache_empty(tmp_path):
    assert summarize_cache(tmp_path) == ["(cache empty)"]


def test_summarize_cache_lists_build_and_rootfs(tmp_path):
    write_manifest(tmp_path, Manifest(kind="build", label="linux-6.6.30-aaaa", key="k",
                                      version="6.6.30", arch="arm64", storage_mode="volume"))
    rimg = tmp_path / "artifacts" / "rootfs" / "rootfs-arm64-bookworm-cccc.img"
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"x" * 2048)
    write_manifest(tmp_path, Manifest(kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k",
                                      version="", arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(rimg)}))
    lines = summarize_cache(tmp_path)
    joined = "\n".join(lines)
    assert "linux-6.6.30-aaaa" in joined and "6.6.30" in joined
    assert "rootfs-arm64-bookworm-cccc" in joined
    assert "build" in joined and "rootfs" in joined


def test_cmd_clean_unknown_label_raises(tmp_path):
    with pytest.raises(CacheError):
        cmd_clean(_FakeContainer(), tmp_path, label="nope", clean_all=False)


def test_cmd_clean_all_removes_every_manifest(tmp_path):
    write_manifest(tmp_path, Manifest(kind="build", label="linux-6.6.30-aaaa", key="k",
                                      version="6.6.30", arch="arm64", storage_mode="volume"))
    write_manifest(tmp_path, Manifest(kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k",
                                      version="", arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(tmp_path / "gone.img")}))
    rc = cmd_clean(_FakeContainer(), tmp_path, label=None, clean_all=True)
    assert rc == 0
    assert cache.list_manifests(tmp_path, "build") == []
    assert cache.list_manifests(tmp_path, "rootfs") == []
