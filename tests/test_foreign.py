from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from likedbg.errors import LikeDbgError
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import detect_arch


def _elf_header(e_machine: bytes) -> bytes:
    # e_ident(16) = magic(4) + class(1)=64bit + data(1)=LE + version(1) + osabi/pad(9);
    # e_type(2) at 16; e_machine(2) at 18 (little-endian).
    e_ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    return e_ident + b"\x02\x00" + e_machine + b"\x00" * 20


def test_detect_arch_x86_64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x3e\x00"))  # EM_X86_64 = 62
    assert detect_arch(v) == "x86_64"


def test_detect_arch_aarch64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\xb7\x00"))  # EM_AARCH64 = 183
    assert detect_arch(v) == "arm64"


def test_detect_arch_non_elf_raises(tmp_path: Path) -> None:
    v = tmp_path / "notelf"
    v.write_bytes(b"MZ\x90\x00not an elf")
    with pytest.raises(ForeignError, match="not an ELF"):
        detect_arch(v)


def test_detect_arch_unknown_machine_raises(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x28\x00"))  # EM_ARM (32-bit) = 40, unsupported
    with pytest.raises(ForeignError, match="e_machine"):
        detect_arch(v)


def test_foreign_error_is_likedbg_error() -> None:
    assert issubclass(ForeignError, LikeDbgError)


def test_foreign_kernel_is_frozen(tmp_path: Path) -> None:
    fk = ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet",
    )
    with pytest.raises(FrozenInstanceError):
        fk.arch = "arm64"  # type: ignore[misc]
