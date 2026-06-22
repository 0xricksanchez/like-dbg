"""Toolchain registry: (compiler, arch) -> kernel make environment.

clang/LLVM is the default universal cross-compiler (one toolchain builds every
arch via ARCH=… LLVM=1); gcc uses per-arch cross prefixes. The registry is the
seam where pinned older toolchains slot in later.
"""

from __future__ import annotations

from dataclasses import dataclass

from likedbg.config import Arch
from likedbg.errors import ConfigError

_GCC_CROSS: dict[Arch, str] = {
    "arm64": "aarch64-linux-gnu-",
    "x86_64": "x86_64-linux-gnu-",
}

_CLANG_PACKAGES: tuple[str, ...] = ("clang", "lld", "llvm")


@dataclass(frozen=True)
class ToolchainEnv:
    make_vars: dict[str, str]
    apt_packages: tuple[str, ...]


def resolve_toolchain(compiler: str, arch: Arch) -> ToolchainEnv:
    if compiler == "clang":
        return ToolchainEnv(make_vars={"ARCH": arch, "LLVM": "1"}, apt_packages=_CLANG_PACKAGES)
    if compiler == "gcc":
        cross = _GCC_CROSS[arch]
        return ToolchainEnv(
            make_vars={"ARCH": arch, "CROSS_COMPILE": cross},
            apt_packages=(f"gcc-{cross.rstrip('-')}",),
        )
    raise ConfigError(
        f"unknown compiler: {compiler!r}",
        remedy="set [kernel_builder] compiler to 'clang' or 'gcc'",
    )
