"""Per-session copy-on-write overlays over the shared rootfs image.

The rootfs cache is keyed by arch + distribution + hostname, deliberately independent of the
kernel, so every built-kernel run on one host shares a single image file. QEMU takes a write lock
on its `-drive`, so a second concurrent guest cannot boot at all:

    Failed to get "write" lock -- is another process using the image?

Each Debugging session therefore boots a qcow2 overlay backed by that shared image. The base is
opened read-only and shared; every guest's writes land in its own overlay. That also stops a guest
from mutating the *cached* image for every later run -- a panic mid-write or a filled disk used to
degrade it for everyone.

The overlay lives beside its base and records a RELATIVE backing name, so it resolves identically
whether QEMU runs on the host (macOS) or inside the debuggee container (Linux), where the mount
layout differs.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from loguru import logger

from likedbg.errors import RootfsError


def overlay_path(base: Path, session_name: str) -> Path:
    """Where this session's overlay lives: beside the base, named for the session."""
    return base.parent / f"{base.name}.{session_name}.qcow2"


def ensure_overlay(container: Any, *, base: Path, session_name: str, image: str) -> Path:
    """The session's overlay, created over `base` if it does not exist yet.

    Reused when present, so `--re-run` keeps whatever the guest wrote; a session that starts under
    a new name gets a clean guest.
    """
    overlay = overlay_path(base, session_name)
    if overlay.is_file():
        logger.info(f"rootfs overlay: reusing {overlay.name}")
        return overlay
    if not base.is_file():
        raise RootfsError(f"rootfs image is missing: {base}", remedy="rebuild it (`start_kgdb --list`)")

    # qemu-img runs in the debuggee image (it ships qemu-utils) rather than on the host, so the
    # host still needs nothing but Docker. cwd is the shared directory and the backing file is
    # named relatively, so the overlay does not bake in a container-only absolute path.
    mount = str(base.parent)
    cmd = f"cd {shlex.quote(mount)} && qemu-img create -f qcow2 -b {shlex.quote(base.name)} -F raw {shlex.quote(overlay.name)}"
    c = container.run_detached(image, volumes={mount: {"bind": mount, "mode": "rw"}}, detach=True, tty=True)
    try:
        container.exec(c, cmd)
    finally:
        container.stop(c)
    if not overlay.is_file():
        raise RootfsError(
            f"could not create the rootfs overlay {overlay}",
            remedy="check that the debuggee image has qemu-img (`start_kgdb --build-images`)",
        )
    logger.info(f"rootfs overlay: created {overlay.name} over {base.name}")
    return overlay


def overlays_for(base: Path) -> list[Path]:
    """Every session overlay stacked on `base` -- what a `--clean` of that rootfs must remove."""
    return sorted(base.parent.glob(f"{base.name}.*.qcow2"))
