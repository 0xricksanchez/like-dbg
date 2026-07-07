"""Foreign-kernel (CTF adopt) host-side logic: arch detection, vmlinux extraction,
initramfs repack, and live console upload. See ADR-0010."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Literal

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
    with vmlinux.open("rb") as f:
        head = f.read(20)
    if head[:4] != b"\x7fELF":
        raise ForeignError(
            f"{vmlinux} is not an ELF file (cannot detect arch)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    if len(head) < 20:
        raise ForeignError(
            f"{vmlinux} is too short to be a valid ELF (truncated header)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    endian: Literal["little", "big"] = "little" if head[5] == 1 else "big"
    e_machine = int.from_bytes(head[18:20], endian)
    arch = _EM_TO_ARCH.get(e_machine)
    if arch is None:
        raise ForeignError(
            f"unsupported ELF e_machine {e_machine} in {vmlinux}",
            remedy="set [foreign].arch to x86_64 or arm64",
        )
    return arch


def extract_vmlinux(container: Any, image_path: Path, out: Path, *, image: str) -> Path:
    """Carve an uncompressed vmlinux ELF from a boot image inside the like_musl container.

    Returns `out` on success. Note: a vmlinux carved from a bzImage is fully stripped
    (kallsyms only, no ELF .symtab) — good for arch-detect, but gdb gets no function symbols
    (see ADR-0010). Raises ForeignError if extraction produces no file.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    c = container.run_detached(
        image,
        volumes={
            str(image_path.parent): {"bind": "/in", "mode": "ro"},
            str(out.parent): {"bind": "/out", "mode": "rw"},
        },
        detach=True,
        tty=True,
    )
    try:
        container.exec(c, f"/opt/extract-vmlinux.sh /in/{image_path.name} /out/{out.name}")
    finally:
        container.stop(c)
    if not out.is_file() or out.stat().st_size == 0:
        raise ForeignError(
            f"could not extract vmlinux from {image_path}",
            remedy="provide [foreign].vmlinux explicitly (arm64 Image / unknown compression)",
        )
    return out
