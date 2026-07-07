"""Typed QEMU argv builder (replaces the legacy string concatenation)."""

from __future__ import annotations

from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.host_profile import HostProfile

_QEMU_BIN = {"arm64": "qemu-system-aarch64", "x86_64": "qemu-system-x86_64"}


def _mitigations(d: DebuggeeCfg) -> list[str]:
    out: list[str] = []
    out.append("nokaslr" if not d.kaslr else "kaslr")
    if not d.smep:
        out.append("nosmep")
    if not d.smap:
        out.append("nosmap")
    out.append("pti=on" if d.kpti else "nopti")
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
    return ["-drive", f"file={rootfs},format=raw,if=virtio"], "root=/dev/vda"


def _foreign_append(cmdline: str, console_dev: str, extra_boot_args: tuple[str, ...]) -> str:
    parts = [cmdline]
    if "console=" not in cmdline:
        parts.append(f"console={console_dev}")
    parts.extend(extra_boot_args)
    return " ".join(p for p in parts if p)


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
    if foreign_cmdline is not None:
        append = _foreign_append(foreign_cmdline, console_dev, extra_boot_args)
    else:
        append = " ".join(
            [
                console,
                root,
                "earlyprintk=serial",
                "net.ifnames=0",
                *_mitigations(debuggee),
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
    if debuggee.share and share_host_dir is not None:
        argv += ["-virtfs", f"local,path={share_host_dir},mount_tag=exploit,security_model=mapped-xattr,id=fsdev0"]
    if debuggee.gdb:
        argv += ["-S", "-gdb", f"tcp::{debuggee.gdb_port}"]
    argv += list(qemu_extra)
    return argv
