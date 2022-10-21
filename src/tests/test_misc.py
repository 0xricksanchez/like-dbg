from src.misc import *
import pytest
import uuid
from pathlib import Path


def test_cross_compile() -> None:
    assert cross_compile("arm64") == "aarch64-linux-gnu-"
    assert cross_compile("riscv64") == "riscv64-linux-gnu-"
    assert cross_compile("X8664") == "x86_64-pc-linux-gnu-"


def test_adjust_toolchain_arch() -> None:
    assert adjust_toolchain_arch("arm64") == "aarch64"
    assert adjust_toolchain_arch("x86_64") == "x86-64"
    assert adjust_toolchain_arch("foo") == "foo"


def test_adjust_arch() -> None:
    assert adjust_arch("riscv64") == "riscv"
    assert adjust_arch("x86_64") == "x86_64"
    assert adjust_arch("arm64") == "arm64"
    with pytest.raises(SystemExit) as ext:
        adjust_arch("foo")
    assert ext.type == SystemExit
    assert ext.value.code == -1


def test_adjust_qemu_arch() -> None:
    assert adjust_qemu_arch("arm64") == "aarch64"
    assert adjust_qemu_arch("foo") == "foo"


def test_get_sha256_from_file() -> None:
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    p.touch()
    p.write_text("FOOBAR")
    assert get_sha256_from_file(p) == "24c422e681f1c1bd08286c7aaf5d23a5f088dcdb0b219806b3a9e579244f00c5"
    p.unlink()
