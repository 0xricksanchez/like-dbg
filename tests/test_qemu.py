from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv


def _host(arch_accel="hvf", mode="native-host"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        accel=arch_accel,
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )


def _settings(arch="arm64", **debuggee):
    base = {"memory": 1024, "smp": 1, "gdb": True, "kaslr": False}
    base.update(debuggee)
    return Settings.model_validate({"general": {"arch": arch}, "debuggee": base})


def _argstr(argv):
    return " ".join(argv)


def test_arm64_hvf_machine_and_accel():
    argv = build_qemu_argv(_settings("arm64"), _host("hvf"), kernel_image=Path("/w/Image"), rootfs=None)
    assert argv[0] == "qemu-system-aarch64"
    s = _argstr(argv)
    assert "-M virt" in s and "-accel hvf" in s and "-kernel /w/Image" in s


def test_gdbstub_flags_present_when_gdb_enabled():
    argv = build_qemu_argv(_settings("arm64", gdb=True), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-S" in argv and "-s" in argv


def test_no_gdbstub_when_disabled():
    argv = build_qemu_argv(_settings("arm64", gdb=False), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-S" not in argv


def test_nokaslr_in_append_when_kaslr_false():
    argv = build_qemu_argv(_settings("arm64", kaslr=False), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    append = argv[argv.index("-append") + 1]
    assert "nokaslr" in append and "console=ttyAMA0" in append


def test_cpio_rootfs_uses_initrd():
    argv = build_qemu_argv(_settings("arm64"), _host(), kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.cpio.gz"))
    s = _argstr(argv)
    assert "-initrd /w/rootfs.cpio.gz" in s


def test_ext4_rootfs_uses_drive():
    argv = build_qemu_argv(_settings("arm64"), _host(), kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.img"))
    s = _argstr(argv)
    assert "-drive" in s and "rootfs.img" in s
