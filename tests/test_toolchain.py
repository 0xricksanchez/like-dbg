import pytest

from likedbg.errors import ConfigError
from likedbg.toolchain import resolve_toolchain


def test_clang_arm64_is_llvm_no_cross_compile():
    env = resolve_toolchain("clang", "arm64")
    assert env.make_vars["ARCH"] == "arm64"
    assert env.make_vars["LLVM"] == "1"
    assert "CROSS_COMPILE" not in env.make_vars
    assert any("clang" in p or "llvm" in p for p in env.apt_packages)


def test_clang_x86_64_arch_name():
    env = resolve_toolchain("clang", "x86_64")
    assert env.make_vars["ARCH"] == "x86_64"
    assert env.make_vars["LLVM"] == "1"


def test_gcc_arm64_uses_cross_prefix_and_pkg():
    env = resolve_toolchain("gcc", "arm64")
    assert env.make_vars["CROSS_COMPILE"] == "aarch64-linux-gnu-"
    assert "LLVM" not in env.make_vars
    assert "gcc-aarch64-linux-gnu" in env.apt_packages


def test_unknown_compiler_raises():
    with pytest.raises(ConfigError):
        resolve_toolchain("tcc", "arm64")
