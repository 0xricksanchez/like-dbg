from pathlib import Path

from likedbg.cache import locations
from likedbg.cache import tree_mount_source


def test_volume_mode_footprint():
    label = "linux-6.6.30-gef-a1b2c3d4"
    loc = locations(label, arch="arm64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.objdir == f"/ksrc/obj/{label}"
    assert loc.image_in_tree == f"/ksrc/obj/{label}/arch/arm64/boot/Image"
    assert loc.image_host == f"/ws/artifacts/{label}/Image"
    assert loc.gdb_mount_source == "likedbg_ksrc"
    assert loc.gdb_mount_type == "volume"
    assert loc.gdb_vmlinux == f"/ksrc/obj/{label}/vmlinux"
    # no src_label given -> source_root is empty
    assert loc.source_root == ""


def test_volume_mode_source_root_with_src_label():
    label = "linux-6.6.30-gef-a1b2c3d4"
    src_label = "linux-6.6.30-gef-deadbeef"
    loc = locations(label, arch="arm64", storage_mode="volume", workspace=Path("/ws"), src_label=src_label)
    assert loc.source_root == f"/ksrc/src/{src_label}"
    assert loc.objdir == f"/ksrc/obj/{label}"


def test_bind_mode_footprint_is_symmetric_and_host_in_tree():
    label = "linux-6.6.30-gef-a1b2c3d4"
    loc = locations(label, arch="x86_64", storage_mode="bind", workspace=Path("/ws"))
    # container-side paths are identical to volume mode (mode-invariant)
    assert loc.objdir == f"/ksrc/obj/{label}"
    assert loc.image_in_tree == f"/ksrc/obj/{label}/arch/x86_64/boot/bzImage"
    assert loc.gdb_vmlinux == f"/ksrc/obj/{label}/vmlinux"
    # image_host is the REAL host in-tree file (no export step in bind)
    assert loc.image_host == f"/ws/artifacts/ksrc/obj/{label}/arch/x86_64/boot/bzImage"
    # the tree's mount source is the parent ksrc dir, mounted at /ksrc (unchanged)
    assert loc.gdb_mount_source == "/ws/artifacts/ksrc"
    assert loc.gdb_mount_type == "bind"
    # the helper returns the same source (used rw by build/unpack, ro by gdb)
    assert tree_mount_source(Path("/ws"), storage_mode="bind") == "/ws/artifacts/ksrc"
    assert tree_mount_source(Path("/ws"), storage_mode="volume") == "likedbg_ksrc"
    # no src_label given -> source_root is empty
    assert loc.source_root == ""


def test_bind_mode_source_root_with_src_label():
    label = "linux-6.6.30-gef-a1b2c3d4"
    src_label = "linux-6.6.30-gef-deadbeef"
    loc = locations(label, arch="x86_64", storage_mode="bind", workspace=Path("/ws"), src_label=src_label)
    assert loc.source_root == f"/ksrc/src/{src_label}"
    assert loc.objdir == f"/ksrc/obj/{label}"


def test_x86_uses_bzimage():
    loc = locations("linux-6.6.30-x-deadbeef", arch="x86_64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.image_in_tree.endswith("/arch/x86_64/boot/bzImage")
