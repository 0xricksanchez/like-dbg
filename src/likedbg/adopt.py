"""One-time migration of the legacy unkeyed /ksrc/linux-<version> tree into the Build Cache,
verified against the active config (version + compiler family) before adoption. See spec §4.5."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
from likedbg.errors import CacheError


def _parse_makefile_version(text: str) -> str:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
            if line.startswith(key) and "=" in line:
                fields[key] = line.split("=", 1)[1].strip()
    return f"{fields.get('VERSION')}.{fields.get('PATCHLEVEL')}.{fields.get('SUBLEVEL')}"


def adopt_legacy_build(container: Any, *, workspace: Path, recipe: BuildRecipe, volume: str = KERNEL_VOLUME) -> str:
    legacy = f"{VOLUME_MOUNT}/linux-{recipe.version}"
    label = recipe.label
    loc = cache.locations(label, arch=recipe.arch, storage_mode="volume", workspace=workspace, volume=volume)
    c = container.run_detached(
        BASE_IMAGE, volumes={volume: {"bind": VOLUME_MOUNT, "mode": "rw"}}, detach=True, tty=True
    )
    try:
        version = _parse_makefile_version(container.exec(c, f"cat {legacy}/Makefile").output)
        if version != recipe.version:
            raise CacheError(
                f"legacy tree is {version}, active config is {recipe.version}",
                remedy="set the matching version, or build fresh",
            )
        cc = container.exec(c, f"grep CC_VERSION_TEXT {legacy}/.config || true").output.lower()
        if recipe.compiler not in cc:
            raise CacheError(
                f"legacy tree compiler != {recipe.compiler!r} (.config: {cc.strip()})",
                remedy="set the matching compiler, or build fresh",
            )
        container.exec(c, f"test -e {legacy}/vmlinux")
        container.exec(c, f"mv {legacy} {VOLUME_MOUNT}/{label}")
    finally:
        container.stop(c)
    cache.write_manifest(
        workspace,
        cache.Manifest(
            kind="build",
            label=label,
            key=recipe.key,
            version=recipe.version,
            arch=recipe.arch,
            storage_mode="volume",
            inputs=recipe.cache_inputs(),
            paths={
                "kernel_root": loc.kernel_root,
                "vmlinux_in_tree": loc.vmlinux_in_tree,
                "image_in_tree": loc.image_in_tree,
                "image_host": loc.image_host,
                "gdb_mount_source": loc.gdb_mount_source,
                "gdb_mount_type": loc.gdb_mount_type,
                "gdb_vmlinux": loc.gdb_vmlinux,
            },
        ),
    )
    return label
