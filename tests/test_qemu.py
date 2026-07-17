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


def test_foreign_cmdline_used_verbatim_no_mitigations():
    argv = build_qemu_argv(
        _debuggee(kaslr=False),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=Path("/w/initramfs.cpio.gz"),
        foreign_cmdline="quiet console=ttyS0 kaslr",
    )
    append = argv[argv.index("-append") + 1]
    assert append.startswith("quiet console=ttyS0 kaslr")
    # no imposed mitigation/root/panic tokens
    for tok in ("nokaslr", "nosmep", "nosmap", "pti=on", "root=/dev/ram", "oops=panic", "panic="):
        assert tok not in append


def test_foreign_explicit_toml_mitigations_replace_conflicting_cmdline_tokens():
    argv = build_qemu_argv(
        _debuggee(kaslr=False, kpti=False),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0 kaslr pti=on mitigations=auto",
        foreign_mitigation_overrides=("kaslr", "kpti", "mitigations"),
    )
    append = argv[argv.index("-append") + 1]
    assert "kaslr" not in append.split() and "pti=on" not in append.split() and "mitigations=auto" not in append.split()
    assert append.endswith("nokaslr nopti mitigations=off")


def test_foreign_explicit_kaslr_toggle_preserves_other_verbatim_arguments():
    argv = build_qemu_argv(
        _debuggee(kaslr=True),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0 nokaslr panic=-1",
        foreign_mitigation_overrides=("kaslr",),
    )
    append = argv[argv.index("-append") + 1]
    assert append == "quiet console=ttyS0 panic=-1 kaslr"


def test_foreign_cmdline_adds_console_when_missing():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet",
    )
    append = argv[argv.index("-append") + 1]
    assert "console=ttyS0" in append


def test_foreign_cmdline_arm64_console_ttyama0():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="arm64"),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        foreign_cmdline="quiet",
    )
    append = argv[argv.index("-append") + 1]
    assert "console=ttyAMA0" in append


def test_foreign_cmdline_layers_extra_boot_args():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0",
        extra_boot_args=("nokaslr",),
    )
    append = argv[argv.index("-append") + 1]
    assert append.endswith("nokaslr")


def test_foreign_initramfs_uses_initrd_and_gdbstub():
    argv = build_qemu_argv(
        _debuggee(gdb=True),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=Path("/w/initramfs.cpio.gz"),
        foreign_cmdline="quiet console=ttyS0",
    )
    s = _argstr(argv)
    assert "-initrd /w/initramfs.cpio.gz" in s
    assert "-S" in argv and "tcp::1234" in argv


def test_qemu_extra_appended_to_argv():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0",
        qemu_extra=("-no-reboot", "-monitor", "none"),
    )
    assert "-no-reboot" in argv and "-monitor" in argv and "none" in argv
    # appears after the gdbstub block
    assert argv.index("-no-reboot") > argv.index("-gdb")


def test_qemu_extra_empty_by_default_keeps_existing_argv():
    argv = build_qemu_argv(_debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None)
    assert "nokaslr" in argv[argv.index("-append") + 1]  # normal path unchanged


def _append(debuggee, target_arch):
    argv = build_qemu_argv(
        debuggee, _host(target_arch=target_arch), target_arch=target_arch, kernel_image=Path("/w/Image"), rootfs=None
    )
    return argv[argv.index("-append") + 1]


def test_x86_64_default_append_is_byte_identical_baseline():
    # fgkaslr defaults on and the tri-state hints default unset, so the x86_64 default cmdline is unchanged.
    ap = _append(_debuggee(), "x86_64")
    assert "pti=on" in ap  # kpti default on
    assert "nofgkaslr" not in ap and "nosmep" not in ap and "nosmap" not in ap
    for tok in ("mitigations=", "slab_nomerge", "slab_merge", "init_on_alloc", "init_on_free", "hardened_usercopy"):
        assert tok not in ap


def test_arm64_default_append_omits_x86_only_params():
    ap = _append(_debuggee(), "arm64")
    assert "nokaslr" in ap
    # pti=/nopti, nosmep/nosmap and nofgkaslr are x86-only; kpti default on emits nothing on arm64.
    for tok in ("pti=on", "nopti", "nosmep", "nosmap", "nofgkaslr"):
        assert tok not in ap


def test_kpti_disable_is_arch_correct():
    assert "nopti" in _append(_debuggee(kpti=False), "x86_64")
    ap_arm = _append(_debuggee(kpti=False), "arm64")
    assert "kpti=off" in ap_arm and "nopti" not in ap_arm and "pti=on" not in ap_arm


def test_fgkaslr_disable_is_x86_only():
    assert "nofgkaslr" in _append(_debuggee(fgkaslr=False), "x86_64")
    assert "nofgkaslr" not in _append(_debuggee(fgkaslr=False), "arm64")


def test_smep_smap_controlled_via_cpu_flags_not_boot_args():
    # SMEP/SMAP are x86_64 -cpu features; the nosmep/nosmap boot args were removed from mainline (5.18/5.19).
    off = build_qemu_argv(
        _debuggee(smep=False, smap=False),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
    )
    s_off = _argstr(off)
    assert "+smep" not in s_off and "+smap" not in s_off  # dropped from the -cpu model
    ap_off = off[off.index("-append") + 1]
    assert "nosmep" not in ap_off and "nosmap" not in ap_off  # no dead boot args
    on = build_qemu_argv(
        _debuggee(smep=True, smap=True),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
    )
    assert "+smep" in _argstr(on) and "+smap" in _argstr(on)


def test_mitigations_off_suppresses_forced_pti_on_x86():
    # mitigations=off is the master switch; an explicit pti=on would override it, so it is not emitted.
    ap = _append(_debuggee(mitigations=False), "x86_64")  # kpti default on
    assert "mitigations=off" in ap
    assert "pti=on" not in ap and "nopti" not in ap
    # arm64 has no conflicting pti= token; mitigations=off stands alone.
    assert "mitigations=off" in _append(_debuggee(mitigations=False), "arm64")


def test_tristate_hints_emit_when_set():
    ap = _append(
        _debuggee(
            mitigations=False,
            slab_merge=False,
            init_on_alloc=True,
            init_on_free=False,
            randomize_kstack_offset=True,
            hardened_usercopy=False,
        ),
        "x86_64",
    )
    assert "mitigations=off" in ap
    assert "slab_nomerge" in ap
    assert "init_on_alloc=1" in ap
    assert "init_on_free=0" in ap
    assert "randomize_kstack_offset=on" in ap
    assert "hardened_usercopy=off" in ap


def test_tristate_true_forces_on_variants():
    ap = _append(_debuggee(mitigations=True, slab_merge=True, randomize_kstack_offset=False), "arm64")
    assert "mitigations=auto" in ap
    assert "slab_merge" in ap and "slab_nomerge" not in ap
    assert "randomize_kstack_offset=off" in ap
