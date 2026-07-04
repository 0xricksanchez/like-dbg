from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv


def _host(arch_accel="hvf", mode="native-host", target_arch="arm64"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=target_arch,
        accel=arch_accel,
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )


def _debuggee(**kw):
    base = {"memory_mib": 1024, "smp": 1, "gdb": True, "kaslr": False}
    base.update(kw)
    return DebuggeeCfg(**base)


def _argstr(argv):
    return " ".join(argv)


def test_arm64_hvf_machine_and_accel():
    argv = build_qemu_argv(_debuggee(), _host("hvf"), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None)
    assert argv[0] == "qemu-system-aarch64"
    s = _argstr(argv)
    assert "-M virt" in s and "-accel hvf" in s and "-kernel /w/Image" in s


def test_gdbstub_flags_present_when_gdb_enabled():
    argv = build_qemu_argv(
        _debuggee(gdb=True), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "-S" in argv
    assert "-gdb" in argv and "tcp::1234" in argv
    assert "-s" not in argv  # replaced by the explicit -gdb form


def test_no_gdbstub_when_disabled():
    argv = build_qemu_argv(
        _debuggee(gdb=False), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "-S" not in argv


def test_nokaslr_in_append_when_kaslr_false():
    argv = build_qemu_argv(
        _debuggee(kaslr=False), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    append = argv[argv.index("-append") + 1]
    assert "nokaslr" in append and "console=ttyAMA0" in append


def test_append_disables_predictable_nic_names():
    argv = build_qemu_argv(
        _debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.img")
    )
    append = argv[argv.index("-append") + 1]
    assert "net.ifnames=0" in append


def test_cpio_rootfs_uses_initrd():
    argv = build_qemu_argv(
        _debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.cpio.gz")
    )
    s = _argstr(argv)
    assert "-initrd /w/rootfs.cpio.gz" in s


def test_ext4_rootfs_uses_drive():
    argv = build_qemu_argv(
        _debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.img")
    )
    s = _argstr(argv)
    assert "-drive" in s and "rootfs.img" in s


def test_gdb_port_is_configurable():
    argv = build_qemu_argv(
        _debuggee(gdb=True, gdb_port=4444), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "tcp::4444" in argv


def test_arm64_kvm_uses_cpu_host():
    argv = build_qemu_argv(
        _debuggee(), _host("kvm", "in-container"), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "-cpu host" in _argstr(argv)


def test_arm64_tcg_uses_cortex_a72():
    argv = build_qemu_argv(
        _debuggee(), _host("tcg", "in-container"), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "-cpu cortex-a72" in _argstr(argv)


def test_x86_64_keeps_qemu64_features_under_kvm():
    argv = build_qemu_argv(
        _debuggee(),
        _host("kvm", "in-container", target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
    )
    s = _argstr(argv)
    assert "qemu64" in s and "+smep" in s and "+smap" in s  # toggles preserved even under KVM


def test_extra_boot_args_spliced_into_append_before_oops():
    argv = build_qemu_argv(
        _debuggee(kaslr=False),
        _host(),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        extra_boot_args=("slub_debug=FZP", "kasan=1"),
    )
    append = argv[argv.index("-append") + 1]
    assert "slub_debug=FZP" in append and "kasan=1" in append
    # extra args must appear before oops=panic
    assert append.index("slub_debug=FZP") < append.index("oops=panic")


def test_effective_debuggee_kaslr_false_yields_nokaslr():
    eff = DebuggeeCfg(kaslr=False, memory_mib=2048)
    argv = build_qemu_argv(
        eff,
        _host(),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        extra_boot_args=("slub_debug=FZP",),
    )
    append = argv[argv.index("-append") + 1]
    assert "nokaslr" in append and "slub_debug=FZP" in append
    assert "2048" in argv


def test_console_log_uses_chardev_logfile_not_nographic():
    argv = build_qemu_argv(
        _debuggee(),
        _host(),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        console_log=Path("/run/logs/console.raw"),
    )
    s = _argstr(argv)
    assert "-chardev" in argv
    assert "stdio,id=cons,logfile=/run/logs/console.raw,signal=off" in s
    assert "-serial chardev:cons" in s
    assert "-display none" in s
    assert "-nographic" not in argv


def test_no_console_log_keeps_nographic():
    argv = build_qemu_argv(_debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None)
    assert "-nographic" in argv
    assert "-chardev" not in argv
