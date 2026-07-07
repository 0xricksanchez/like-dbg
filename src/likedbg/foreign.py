"""Foreign-kernel (CTF adopt) host-side logic: arch detection, vmlinux extraction,
initramfs repack, and live console upload. See ADR-0010."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from likedbg.errors import LikeDbgError

_EM_TO_ARCH = {62: "x86_64", 183: "arm64"}  # EM_X86_64, EM_AARCH64


class ForeignError(LikeDbgError):
    """A foreign-kernel adopt/boot/exploit-delivery operation could not be set up."""


@dataclass(frozen=True)
class ForeignKernel:
    image: Path
    vmlinux: Path
    initramfs: Path | None
    arch: str
    cmdline: str


def detect_arch(vmlinux: Path) -> str:
    """Return 'x86_64'/'arm64' from the ELF e_machine, else raise ForeignError."""
    head = vmlinux.read_bytes()[:20]
    if head[:4] != b"\x7fELF":
        raise ForeignError(
            f"{vmlinux} is not an ELF file (cannot detect arch)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    endian = "little" if head[5] == 1 else "big"
    e_machine = int.from_bytes(head[18:20], endian)  # type: ignore[arg-type]
    arch = _EM_TO_ARCH.get(e_machine)
    if arch is None:
        raise ForeignError(
            f"unsupported ELF e_machine {e_machine} in {vmlinux}",
            remedy="set [foreign].arch to x86_64 or arm64",
        )
    return arch
