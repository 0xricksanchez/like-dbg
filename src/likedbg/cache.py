"""Content-addressed Build Cache: Recipe value objects (single source of truth for what a
Kernel Build / rootfs is), key + Label derivation, the host-side Manifest registry, and
storage-mode-aware location resolution.

See docs/superpowers/specs/2026-06-23-build-reuse-cache-design.md and ADR-0003: a Kernel
Build is identified by its requested configuration, not by toolchain/image identity.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from likedbg.config import Settings
from likedbg.toolchain import resolve_toolchain

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def cache_key(inputs: dict[str, str]) -> str:
    blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def short_hash(key: str) -> str:
    return key[:8]


def slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")


@dataclass(frozen=True)
class BuildRecipe:
    version: str
    arch: str
    compiler: str
    make_vars: tuple[tuple[str, str], ...]
    frag_hashes: tuple[tuple[str, str], ...]
    fragments: tuple[str, ...]
    kernel_tag: str = ""

    def env(self) -> dict[str, str]:
        return dict(self.make_vars)

    def cache_inputs(self) -> dict[str, str]:
        inputs = {"version": self.version, "arch": self.arch, "compiler": self.compiler}
        inputs.update({f"frag:{name}": h for name, h in self.frag_hashes})
        return inputs

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        tag = f"-{slug(self.kernel_tag)}" if self.kernel_tag else ""
        return f"linux-{slug(self.version)}{tag}-{short_hash(self.key)}"


@dataclass(frozen=True)
class RootfsRecipe:
    arch: str
    distribution: str
    hostname: str

    def cache_inputs(self) -> dict[str, str]:
        return {"arch": self.arch, "distribution": self.distribution, "hostname": self.hostname}

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        return f"rootfs-{slug(self.arch)}-{slug(self.distribution)}-{short_hash(self.key)}"


def build_recipe(settings: Settings, *, version: str, workspace: Path, fragments: list[str]) -> BuildRecipe:
    tc = resolve_toolchain(settings.kernel_builder.compiler, settings.general.arch)
    frag_hashes = sorted(
        (Path(rel).name, hashlib.sha256((workspace / rel).read_bytes()).hexdigest()) for rel in fragments
    )
    return BuildRecipe(
        version=version,
        arch=settings.general.arch,
        compiler=settings.kernel_builder.compiler,
        make_vars=tuple(sorted(tc.make_vars.items())),
        frag_hashes=tuple(frag_hashes),
        fragments=tuple(fragments),
        kernel_tag=settings.general.kernel_tag,
    )


def rootfs_recipe(settings: Settings) -> RootfsRecipe:
    return RootfsRecipe(
        arch=settings.general.arch,
        distribution=settings.rootfs.distribution,
        hostname=settings.rootfs.hostname,
    )
