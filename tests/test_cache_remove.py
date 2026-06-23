from types import SimpleNamespace

import pytest

from likedbg.cache import Manifest
from likedbg.cache import manifest_exists
from likedbg.cache import remove_cached
from likedbg.cache import write_manifest
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_remove_build_rms_volume_tree_and_host_export_and_manifest(tmp_path):
    label = "linux-6.6.30-aaaa"
    write_manifest(
        tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume")
    )
    export = tmp_path / "artifacts" / label
    export.mkdir(parents=True)
    (export / "Image").write_bytes(b"img")
    c = FakeC()
    remove_cached(
        c, tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume")
    )
    assert any(f"rm -rf /ksrc/{label}" in e for e in c.execs)
    assert not export.exists()
    assert manifest_exists(tmp_path, "build", label) is False


def test_remove_rootfs_unlinks_image_and_manifest(tmp_path):
    label = "rootfs-arm64-bookworm-cccc"
    img = tmp_path / "artifacts" / "rootfs" / f"{label}.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(img)},
        ),
    )
    c = FakeC()
    remove_cached(
        c,
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(img)},
        ),
    )
    assert c.execs == []  # rootfs lives on the host; no container needed
    assert not img.exists()
    assert manifest_exists(tmp_path, "rootfs", label) is False


def test_remove_build_refuses_non_volume_storage(tmp_path):
    label = "linux-6.6.30-bbbb"
    m = Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="bind")
    write_manifest(tmp_path, m)
    with pytest.raises(CacheError):
        remove_cached(FakeC(), tmp_path, m)
    # the manifest is preserved (nothing was removed)
    assert manifest_exists(tmp_path, "build", label) is True
