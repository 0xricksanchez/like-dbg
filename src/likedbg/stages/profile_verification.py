"""ProfileVerificationStage: verify the built .config against resolved Debug profile expectations.
Reads host-captured .config + kernel_release (zero per-run containers); legacy manifests fall back
to a one-time helper-container read + backfill."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from likedbg.cache import Manifest
from likedbg.cache import load_manifest
from likedbg.cache import tree_mount_source
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.debug_profiles import RunResolution
from likedbg.debug_profiles import verify_config
from likedbg.errors import BuildError
from likedbg.errors import CacheError
from likedbg.pipeline import PipelineContext


def read_built_config(manifest: Manifest, *, container: ContainerService | None, workspace: Path) -> tuple[str, str]:
    """Return ``(config_text, kernel_release)`` for *manifest*.

    Happy path: reads the host-captured ``.config`` written by BuildStage (Task 9): no
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
        # Strip CRLF from the tty-backed container read (clean LF for both the return value and backfill).
        text = container.exec(c, f"cat {root}/.config").output.replace("\r\n", "\n")
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


class ProfileVerificationStage:
    """Verify the built kernel .config against debug-profile expectations."""

    name = "profile-verification"

    def __init__(self, container: ContainerService | None, *, workspace: Path, kernel_volume: str) -> None:
        self._c = container
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return ctx.run_resolution is None

    def run(self, ctx: PipelineContext) -> PipelineContext:
        rr = ctx.run_resolution
        assert isinstance(rr, RunResolution)

        manifest = load_manifest(self._workspace, "build", ctx.build_label or "")
        config_text, release = read_built_config(manifest, container=self._c, workspace=self._workspace)

        ctx.kernel_release = release
        ctx.config_host = Path(manifest.paths["config_host"]) if manifest.paths.get("config_host") else None

        verification = verify_config(config_text, rr.profiles, target_arch=rr.target_arch, kernel_release=release)

        recorder = ctx.recorder
        if recorder is not None:
            recorder.record_profile_verification(verification)
            recorder.record_kernel_paths(
                config=manifest.paths.get("config_host", ""),
                system_map=f"{manifest.paths['kernel_root']}/System.map",
                vmlinux=manifest.paths.get("gdb_vmlinux", ""),
                image=manifest.paths.get("image_host", ""),
            )

        if verification.missing_hard:
            if recorder is not None:
                recorder.set_status(
                    "profile-verification-failed",
                    message="; ".join(f"{e.symbol}={e.value}" for e in verification.missing_hard),
                )
            first = verification.missing_hard[0]
            raise BuildError(
                f"debug profile verification failed: {rr.profiles.names} requested"
                f" {first.symbol}={first.value}, but the final .config does not satisfy it",
                remedy="inspect artifacts/runs/latest/profiles.json or remove the offending profile",
            )

        for msg in verification.warnings:
            logger.warning(msg)

        return ctx
