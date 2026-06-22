"""Typed QEMU argv builder (replaces the legacy string concatenation)."""

from __future__ import annotations

from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile

_QEMU_BIN = {"arm64": "qemu-system-aarch64", "x86_64": "qemu-system-x86_64"}


def _mitigations(settings: Settings) -> list[str]:
    d = settings.debuggee
    out: list[str] = []
    out.append("nokaslr" if not d.kaslr else "kaslr")
    if not d.smep:
        out.append("nosmep")
    if not d.smap:
        out.append("nosmap")
    out.append("pti=on" if d.kpti else "nopti")
    return out


def _panic(settings: Settings) -> str:
    p = settings.debuggee.panic
    if p == "reboot":
        return "panic=-1"
    if p == "halt":
        return "panic=0"
    return "panic=15"


def _rootfs_args(rootfs: Path | None) -> tuple[list[str], str]:
    if rootfs is None:
        return [], "root=/dev/ram"
    if ".cpio" in rootfs.name:
        return ["-initrd", str(rootfs)], "root=/dev/ram"
    return ["-drive", f"file={rootfs},format=raw,if=virtio"], "root=/dev/vda"


def build_qemu_argv(settings: Settings, host: HostProfile, *, kernel_image: Path, rootfs: Path | None) -> list[str]:
    arch = settings.general.arch
    argv = [_QEMU_BIN[arch]]
    if arch == "arm64":
        argv += ["-M", "virt", "-cpu", "host" if host.accel == "hvf" else "cortex-a72"]
        console = "console=ttyAMA0"
    else:
        cpu = "qemu64"
        if settings.debuggee.smep:
            cpu += ",+smep"
        if settings.debuggee.smap:
            cpu += ",+smap"
        argv += ["-cpu", cpu]
        console = "console=ttyS0"
    argv += ["-accel", host.accel, "-m", str(settings.debuggee.memory), "-smp", str(settings.debuggee.smp)]
    argv += ["-kernel", str(kernel_image)]
    drive_args, root = _rootfs_args(rootfs)
    append = " ".join([console, root, "earlyprintk=serial", *_mitigations(settings), "oops=panic", _panic(settings)])
    argv += ["-append", append, *drive_args, "-nographic"]
    if settings.debuggee.gdb:
        argv += ["-S", "-s"]
    return argv
