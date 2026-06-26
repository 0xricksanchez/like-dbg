"""ProfileVerificationStage: verify the built .config against resolved Debug profile expectations.
Reads host-captured .config + kernel_release (zero per-run containers); legacy manifests fall back
to a one-time helper-container read + backfill."""

from __future__ import annotations

from pathlib import Path

from likedbg.cache import Manifest
from likedbg.cache import tree_mount_source
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError


def read_built_config(manifest: Manifest, *, container: ContainerService | None, workspace: Path) -> tuple[str, str]:
    """Return ``(config_text, kernel_release)`` for *manifest*.

    Happy path: reads the host-captured ``.config`` written by BuildStage (Task 9) — no
    container needed.  Legacy path: falls back to a one-time helper-container read (volume or
    bind mount) and backfills the export path for next time.
    """
    config_host = manifest.paths.get("config_host")
    if config_host and Path(config_host).is_file():
        return Path(config_host).read_text(), manifest.kernel_release

    # Legacy fallback: read from the kernel tree via a short-lived helper container.
    root = manifest.paths["kernel_root"]
    if container is None:
        raise CacheError(
            f"no captured .config for {manifest.label!r}",
            remedy="rebuild without --use to capture host-side artefacts",
        )
    if manifest.storage_mode == "volume":
        c = container.run_detached(
            BASE_IMAGE,
            volumes={KERNEL_VOLUME: {"bind": VOLUME_MOUNT, "mode": "ro"}},
            detach=True,
            tty=True,
        )
    else:
        src = tree_mount_source(workspace, storage_mode=manifest.storage_mode)
        c = container.run_detached(
            BASE_IMAGE,
            volumes={src: {"bind": VOLUME_MOUNT, "mode": "ro"}},
            detach=True,
            tty=True,
        )
    try:
        text = container.exec(c, f"cat {root}/.config").output
        if manifest.kernel_release:
            release = manifest.kernel_release
        else:
            from likedbg.debug_profiles import parse_kernel_release  # noqa: PLC0415

            release = parse_kernel_release(container.exec(c, f"sed -n '1,6p' {root}/Makefile").output)
    finally:
        container.stop(c)

    export = workspace / "artifacts" / manifest.label / "config"
    export.parent.mkdir(parents=True, exist_ok=True)
    export.write_text(text)
    return text, release
