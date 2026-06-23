from pathlib import Path

from likedbg.cache import locations


def test_volume_mode_footprint():
    loc = locations("linux-6.6.30-gef-a1b2c3d4", arch="arm64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.kernel_root == "/ksrc/linux-6.6.30-gef-a1b2c3d4"
    assert loc.image_in_tree == "/ksrc/linux-6.6.30-gef-a1b2c3d4/arch/arm64/boot/Image"
    assert loc.image_host == "/ws/artifacts/linux-6.6.30-gef-a1b2c3d4/Image"
    assert loc.gdb_mount_source == "likedbg_ksrc"
    assert loc.gdb_mount_type == "volume"
    assert loc.gdb_vmlinux == "/ksrc/linux-6.6.30-gef-a1b2c3d4/vmlinux"


def test_bind_mode_footprint_has_no_host_export():
    loc = locations("linux-6.6.30-gef-a1b2c3d4", arch="arm64", storage_mode="bind", workspace=Path("/ws"))
    assert loc.image_host == ""
    assert loc.gdb_mount_type == "bind"
    assert loc.gdb_mount_source == "/ws/artifacts/builds/linux-6.6.30-gef-a1b2c3d4"
    assert loc.gdb_vmlinux == "/ksrc/vmlinux"


def test_x86_uses_bzimage():
    loc = locations("linux-6.6.30-x-deadbeef", arch="x86_64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.image_in_tree.endswith("/arch/x86_64/boot/bzImage")
