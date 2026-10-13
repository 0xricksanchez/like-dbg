"""Typed QEMU argv builder (replaces the legacy string concatenation)."""

from __future__ import annotations

import re
from collections.abc import Collection
from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.foreign import ForeignError
from likedbg.host_profile import HostProfile

_QEMU_BIN = {"arm64": "qemu-system-aarch64", "x86_64": "qemu-system-x86_64"}

_ETHN_RE = re.compile(r"^eth\d+$")
_ENP0S_RE = re.compile(r"^enp0s(\d+)$")


def _foreign_nic_args(net_iface: str, cmdline: str) -> tuple[str, list[str]]:
    """Return (`-device` value, extra kernel-cmdline tokens) for an outbound foreign NIC that the
    guest sees under `net_iface`. The name is matched HOST-SIDE - the initramfs is never edited.
      ethN   -> NIC on an auto PCI slot + net.ifnames=0 (skipped if the cmdline already sets
                net.ifnames=0; a conflicting net.ifnames value raises)
      enp0sN -> NIC pinned to PCI slot N; the challenge's predictable-naming kernel names it enp0sN
    Raises ForeignError on an unsupported scheme or a net.ifnames contradiction (no silent failure)."""
    if _ETHN_RE.match(net_iface):
        if "net.ifnames=" in cmdline and "net.ifnames=0" not in cmdline:
            raise ForeignError(
                f"[foreign].net_iface={net_iface!r} needs net.ifnames=0, but the challenge cmdline "
                "sets a conflicting net.ifnames value",
                remedy="set net_iface to the enp0sN name the challenge expects, or remove net.ifnames from [foreign].cmdline",
            )
        tokens = [] if "net.ifnames=" in cmdline else ["net.ifnames=0"]
        return "virtio-net-pci,netdev=net0", tokens
    m = _ENP0S_RE.match(net_iface)
    if m:
        if "net.ifnames=0" in cmdline:
            raise ForeignError(
                f"[foreign].net_iface={net_iface!r} needs predictable naming, but the challenge "
                "cmdline sets net.ifnames=0",
                remedy="use an ethN name, or remove net.ifnames=0 from [foreign].cmdline",
            )
        return f"virtio-net-pci,netdev=net0,addr=0x{int(m.group(1)):x}", []
    raise ForeignError(
        f"unsupported [foreign].net_iface {net_iface!r}",
        remedy="use ethN or enp0sN; for other schemes place the NIC via [foreign].qemu_extra and set [foreign].net = false",
    )


def _mitigations(d: DebuggeeCfg, arch: str) -> list[str]:
    out: list[str] = ["nokaslr" if not d.kaslr else "kaslr"]
    # SMEP/SMAP are controlled purely via the x86_64 -cpu feature flags (see build_qemu_argv); the
    # mainline nosmep/nosmap boot args were removed in 5.18/5.19, so no cmdline token is emitted here.
    if arch == "x86_64":
        # KPTI on x86 uses pti=/nopti. Skip it when mitigations=off is requested: that master switch
        # already disables PTI, and an explicit pti=on would override it (arch/x86/mm/pti.c precedence).
        if d.mitigations is not False:
            out.append("pti=on" if d.kpti else "nopti")
        # FG-KASLR (x86_64-only, out-of-tree/CTF): disable with nofgkaslr; ignored on kernels without it.
        if not d.fgkaslr:
            out.append("nofgkaslr")
    else:
        # arm64 KPTI is on by default; its param is kpti=, not the x86 pti=/nopti pair.
        if not d.kpti:
            out.append("kpti=off")
    # Tri-state cmdline hints valid on both arches; None leaves the kernel default untouched.
    if d.mitigations is not None:
        out.append("mitigations=auto" if d.mitigations else "mitigations=off")
    if d.slab_merge is not None:
        out.append("slab_merge" if d.slab_merge else "slab_nomerge")
    if d.init_on_alloc is not None:
        out.append(f"init_on_alloc={1 if d.init_on_alloc else 0}")
    if d.init_on_free is not None:
        out.append(f"init_on_free={1 if d.init_on_free else 0}")
    if d.randomize_kstack_offset is not None:
        out.append("randomize_kstack_offset=" + ("on" if d.randomize_kstack_offset else "off"))
    if d.hardened_usercopy is not None:
        out.append("hardened_usercopy=" + ("on" if d.hardened_usercopy else "off"))
    return out


def _panic(d: DebuggeeCfg) -> str:
    if d.panic == "reboot":
        return "panic=-1"
    if d.panic == "halt":
        return "panic=0"
    return "panic=15"


def _rootfs_args(rootfs: Path | None) -> tuple[list[str], str]:
    if rootfs is None:
        return [], "root=/dev/ram"
    if ".cpio" in rootfs.name:
        return ["-initrd", str(rootfs)], "root=/dev/ram"
    # A per-session overlay is qcow2; the shared image itself is raw. Naming the wrong format
    # makes QEMU read a qcow2 header as a filesystem.
    fmt = "qcow2" if rootfs.suffix == ".qcow2" else "raw"
    return ["-drive", f"file={rootfs},format={fmt},if=virtio"], "root=/dev/vda"


def _foreign_append(cmdline: str, console_dev: str, extra_boot_args: tuple[str, ...]) -> str:
    parts = [cmdline]
    if "console=" not in cmdline:
        parts.append(f"console={console_dev}")
    parts.extend(extra_boot_args)
    return " ".join(p for p in parts if p)


_FOREIGN_MITIGATION_KEYS = frozenset(
    {
        "kaslr",
        "kpti",
        "fgkaslr",
        "mitigations",
        "slab_merge",
        "init_on_alloc",
        "init_on_free",
        "randomize_kstack_offset",
        "hardened_usercopy",
    }
)


def _foreign_mitigation_args(d: DebuggeeCfg, arch: str, overrides: Collection[str]) -> tuple[set[str], list[str]]:
    """Return command-line tokens to replace and append for explicit foreign overrides only."""
    remove: set[str] = set()
    add: list[str] = []
    if "kaslr" in overrides:
        remove |= {"kaslr", "nokaslr"}
        add.append("kaslr" if d.kaslr else "nokaslr")
    if "kpti" in overrides or d.mitigations is False and "mitigations" in overrides:
        remove.add("nopti")  # pti= values are filtered below.
    if "kpti" in overrides and d.mitigations is not False:
        if arch == "x86_64":
            add.append("pti=on" if d.kpti else "nopti")
        elif not d.kpti:
            add.append("kpti=off")
    if "fgkaslr" in overrides:
        remove.add("nofgkaslr")
        if not d.fgkaslr:
            add.append("nofgkaslr")
    if "mitigations" in overrides:
        add.append("mitigations=auto" if d.mitigations else "mitigations=off")
    if "slab_merge" in overrides:
        remove |= {"slab_merge", "slab_nomerge"}
        add.append("slab_merge" if d.slab_merge else "slab_nomerge")
    for key, prefix, enabled, disabled in (
        ("init_on_alloc", "init_on_alloc=", "init_on_alloc=1", "init_on_alloc=0"),
        ("init_on_free", "init_on_free=", "init_on_free=1", "init_on_free=0"),
        (
            "randomize_kstack_offset",
            "randomize_kstack_offset=",
            "randomize_kstack_offset=on",
            "randomize_kstack_offset=off",
        ),
        ("hardened_usercopy", "hardened_usercopy=", "hardened_usercopy=on", "hardened_usercopy=off"),
    ):
        if key in overrides:
            remove.add(prefix)
            add.append(enabled if getattr(d, key) else disabled)
    return remove, add


def _apply_foreign_mitigation_overrides(cmdline: str, d: DebuggeeCfg, arch: str, overrides: Collection[str]) -> str:
    """Apply explicit TOML choices without changing an otherwise verbatim foreign cmdline."""
    active = set(overrides) & _FOREIGN_MITIGATION_KEYS
    if not active:
        return cmdline
    remove, add = _foreign_mitigation_args(d, arch, active)
    kept: list[str] = []
    for token in cmdline.split():
        if token in remove:
            continue
        if token.startswith("pti=") and ("kpti" in active or "mitigations" in active and d.mitigations is False):
            continue
        if token.startswith("kpti=") and "kpti" in active:
            continue
        if token.startswith("mitigations=") and "mitigations" in active:
            continue
        if any(token.startswith(prefix) for prefix in remove if prefix.endswith("=")):
            continue
        kept.append(token)
    return " ".join([*kept, *add])


def build_qemu_argv(
    debuggee: DebuggeeCfg,
    host: HostProfile,
    *,
    target_arch: str,
    kernel_image: Path,
    rootfs: Path | None,
    extra_boot_args: tuple[str, ...] = (),
    console_log: Path | None = None,
    share_host_dir: Path | None = None,
    foreign_cmdline: str | None = None,
    foreign_mitigation_overrides: Collection[str] = (),
    foreign_net: bool = False,
    foreign_net_iface: str = "eth0",
    qemu_extra: tuple[str, ...] = (),
) -> list[str]:
    argv = [_QEMU_BIN[target_arch]]
    if target_arch == "arm64":
        cpu = "host" if host.accel in ("hvf", "kvm") else "cortex-a72"
        argv += ["-M", "virt", "-cpu", cpu]
        console_dev = "ttyAMA0"
        console = f"console={console_dev}"
    else:
        cpu = "qemu64"
        if debuggee.smep:
            cpu += ",+smep"
        if debuggee.smap:
            cpu += ",+smap"
        argv += ["-cpu", cpu]
        console_dev = "ttyS0"
        console = f"console={console_dev}"
    argv += ["-accel", host.accel, "-m", str(debuggee.memory_mib), "-smp", str(debuggee.smp)]
    argv += ["-kernel", str(kernel_image)]
    drive_args, root = _rootfs_args(rootfs)
    foreign_nic_device: str | None = None
    if foreign_cmdline is not None:
        cmdline = _apply_foreign_mitigation_overrides(
            foreign_cmdline, debuggee, target_arch, foreign_mitigation_overrides
        )
        net_tokens: list[str] = []
        if foreign_net:
            foreign_nic_device, net_tokens = _foreign_nic_args(foreign_net_iface, cmdline)
        append = _foreign_append(cmdline, console_dev, (*extra_boot_args, *net_tokens))
    else:
        append = " ".join(
            [
                console,
                root,
                "earlyprintk=serial",
                "net.ifnames=0",
                *_mitigations(debuggee, target_arch),
                *extra_boot_args,
                "oops=panic",
                _panic(debuggee),
            ]
        )
    argv += ["-append", append, *drive_args]
    if console_log is not None:
        argv += [
            "-chardev",
            f"stdio,id=cons,logfile={console_log},signal=off",
            "-serial",
            "chardev:cons",
            "-display",
            "none",
        ]
    else:
        argv += ["-nographic"]
    if debuggee.guest_net:
        argv += ["-netdev", f"user,id=net0,hostfwd=tcp::{debuggee.ssh_port}-:22"]
        argv += ["-device", "virtio-net-pci,netdev=net0"]
    # Foreign outbound NIC. Shares id=net0 with the guest_net block above; the two are
    # mutually exclusive (cmd_foreign forces guest_net=False for a foreign guest), so only one emits.
    if foreign_nic_device is not None:
        argv += ["-netdev", "user,id=net0", "-device", foreign_nic_device]
    if debuggee.share and share_host_dir is not None:
        argv += ["-virtfs", f"local,path={share_host_dir},mount_tag=exploit,security_model=mapped-xattr,id=fsdev0"]
    if debuggee.gdbstub:
        argv += ["-S", "-gdb", f"tcp::{debuggee.gdbstub_port}"]
    argv += list(qemu_extra)
    return argv
