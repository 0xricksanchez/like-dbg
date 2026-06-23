import pytest

from likedbg.cache import Manifest
from likedbg.cache import list_manifests
from likedbg.cache import load_manifest
from likedbg.cache import manifest_exists
from likedbg.cache import manifest_path
from likedbg.cache import write_manifest
from likedbg.errors import CacheError


def _m() -> Manifest:
    return Manifest(
        kind="build",
        label="linux-6.6.30-gef-a1b2c3d4",
        key="deadbeef",
        version="6.6.30",
        arch="arm64",
        storage_mode="volume",
        inputs={"version": "6.6.30"},
        paths={"kernel_root": "/ksrc/linux-6.6.30-gef-a1b2c3d4"},
    )


def test_manifest_path_layout(tmp_path):
    p = manifest_path(tmp_path, "build", "linux-6.6.30-gef-a1b2c3d4")
    assert p == tmp_path / "artifacts" / "cache" / "builds" / "linux-6.6.30-gef-a1b2c3d4.json"


def test_manifest_path_rootfs_kind_is_not_double_pluralized(tmp_path):
    # "rootfs" must map to the "rootfs" dir, NOT "rootfss" (spec §4.3).
    p = manifest_path(tmp_path, "rootfs", "rootfs-arm64-bookworm-deadbeef")
    assert p == tmp_path / "artifacts" / "cache" / "rootfs" / "rootfs-arm64-bookworm-deadbeef.json"


def test_write_then_load_roundtrip(tmp_path):
    assert manifest_exists(tmp_path, "build", _m().label) is False
    write_manifest(tmp_path, _m())
    assert manifest_exists(tmp_path, "build", _m().label) is True
    loaded = load_manifest(tmp_path, "build", _m().label)
    assert loaded == _m()


def test_load_absent_raises_cacheerror(tmp_path):
    with pytest.raises(CacheError):
        load_manifest(tmp_path, "build", "nope")


def test_load_malformed_raises_cacheerror(tmp_path):
    p = manifest_path(tmp_path, "build", "bad")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json")
    with pytest.raises(CacheError):
        load_manifest(tmp_path, "build", "bad")


def test_list_manifests_empty_when_no_dir(tmp_path):
    assert list_manifests(tmp_path, "build") == []


def test_list_manifests_returns_all_of_a_kind_sorted(tmp_path):
    for label in ("linux-6.6.30-bbbb", "linux-6.1.0-aaaa"):
        write_manifest(
            tmp_path, Manifest(kind="build", label=label, key="k", version="x", arch="arm64", storage_mode="volume")
        )
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k", version="", arch="arm64", storage_mode="volume"
        ),
    )
    builds = list_manifests(tmp_path, "build")
    assert [m.label for m in builds] == ["linux-6.1.0-aaaa", "linux-6.6.30-bbbb"]
    assert [m.label for m in list_manifests(tmp_path, "rootfs")] == ["rootfs-arm64-bookworm-cccc"]
