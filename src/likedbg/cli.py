"""Top-level assembly: compose the pipeline + launchers + tmux session into one command."""

from __future__ import annotations

import argparse
import os
import urllib.request
from datetime import UTC
from datetime import datetime
from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg import docker_env
from likedbg.adopt import adopt_legacy_build
from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import RootfsRecipe
from likedbg.cache import build_recipe as make_build_recipe
from likedbg.cache import rootfs_recipe as make_rootfs_recipe
from likedbg.config import load_settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import HostCapabilityError
from likedbg.errors import LikeDbgError
from likedbg.host_profile import HostProfile
from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_pane_command
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext
from likedbg.session import Session
from likedbg.stages.build import BuildStage
from likedbg.stages.debuggee import DebuggeeStage
from likedbg.stages.debugger import DebuggerStage
from likedbg.stages.download import DownloadStage
from likedbg.stages.download import resolve_version
from likedbg.stages.export import ArtifactExporter
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.unpack import UnpackStage

_FRAGMENTS = (
    "configs/fragments/debug.config",
    "configs/fragments/no-kaslr.config",
    "configs/fragments/generic.config",
)


def _fetch(url: str, dest: Path) -> None:
    urllib.request.urlretrieve(url, str(dest))  # noqa: S310


def build_pipeline(
    container: ContainerService,
    session: Session,
    *,
    workspace: Path,
    kernel_volume: str,
    dl_dir: Path,
    debugger_image: str,
    ext: str,
    panes: tuple[int, int],
    build_recipe: BuildRecipe,
    rootfs_recipe: RootfsRecipe,
) -> Pipeline:
    debuggee_pane, debugger_pane = panes

    def launch_qemu(argv: list[str]) -> None:
        session.select_pane(debuggee_pane)
        session.send_keys(qemu_pane_command(argv))

    def run_gdb(args: list[str]) -> None:
        loc = cache.locations(
            build_recipe.label,
            arch=build_recipe.arch,
            storage_mode="volume",  # volume mode enforced upstream by require_volume_mode
            workspace=workspace,
            volume=kernel_volume,
        )
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, mount_source=loc.gdb_mount_source))

    return Pipeline(
        [
            DownloadStage(_fetch, dl_dir=dl_dir),
            UnpackStage(container, kernel_volume=kernel_volume, workspace=workspace),
            BuildStage(
                container,
                recipe=build_recipe,
                kbuilder_image="like_kbuilder_arm64:latest",
                workspace=workspace,
                kernel_volume=kernel_volume,
            ),
            RootfsStage(
                container,
                recipe=rootfs_recipe,
                rootfs_image="like_rootfs:latest",
                workspace=workspace,
            ),
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_qemu),
            DebuggerStage(ext=ext, run_gdb=run_gdb, breakpoint="start_kernel"),
        ]
    )


def build_use_pipeline(
    container: ContainerService,
    session: Session,
    *,
    workspace: Path,
    kernel_volume: str,
    debugger_image: str,
    ext: str,
    panes: tuple[int, int],
    gdb_mount_source: str,
) -> Pipeline:
    debuggee_pane, debugger_pane = panes

    def launch_qemu(argv: list[str]) -> None:
        session.select_pane(debuggee_pane)
        session.send_keys(qemu_pane_command(argv))

    def run_gdb(args: list[str]) -> None:
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, mount_source=gdb_mount_source))

    return Pipeline(
        [
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_qemu),
            DebuggerStage(ext=ext, run_gdb=run_gdb, breakpoint="start_kernel"),
        ]
    )


def cmd_use(
    container: ContainerService,
    session: Session,
    workspace: Path,
    *,
    custom_ini: Path | None,
    label: str,
    rootfs_label: str | None,
    panes: tuple[int, int],
) -> int:
    if not cache.manifest_exists(workspace, "build", label):
        raise CacheError(f"no cached build labelled {label!r}", remedy="run `start_kgdb --list`")
    bm = cache.load_manifest(workspace, "build", label)
    # Build identity (arch) is authoritative; reload settings with the arch override so the
    # host profile / QEMU follow the cached build, keeping runtime+debugger prefs from config.
    use_settings = load_settings(
        workspace / "configs" / "system.ini",
        workspace / "configs" / "user.ini",
        custom_ini=custom_ini,
        overrides={"general": {"arch": bm.arch}},
    )
    host = HostProfile.detect(use_settings, workspace)
    require_volume_mode(host)
    rlabel = rootfs_label or make_rootfs_recipe(use_settings).label
    if not cache.manifest_exists(workspace, "rootfs", rlabel):
        raise CacheError(
            f"no cached rootfs labelled {rlabel!r}",
            remedy="run `start_kgdb` once to build a rootfs, or pass --rootfs <label> (see `--list`)",
        )
    rm = cache.load_manifest(workspace, "rootfs", rlabel)
    rootfs_image = Path(rm.paths["image_host"])
    if not rootfs_image.is_file():
        raise CacheError(f"cached rootfs {rlabel} image is gone", remedy=f"`start_kgdb --clean {rlabel}` and rebuild")
    ctx = PipelineContext(
        settings=use_settings,
        host=host,
        kernel_root=Path(bm.paths["kernel_root"]),
        vmlinux=Path(bm.paths["gdb_vmlinux"]),
        kernel_image=Path(bm.paths["image_in_tree"]),
        rootfs_image=rootfs_image,
        build_label=label,
        rootfs_label=rlabel,
    )
    pipeline = build_use_pipeline(
        container,
        session,
        workspace=workspace,
        kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest",
        ext=use_settings.debugger.ext,
        panes=panes,
        gdb_mount_source=bm.paths["gdb_mount_source"],
    )
    pipeline.run(ctx)
    return 0


def require_volume_mode(host: HostProfile) -> None:
    if host.storage_mode != "volume":
        raise HostCapabilityError(
            f"build-cache runtime supports volume storage only (got {host.storage_mode!r})",
            remedy="this milestone targets macOS volume mode; bind/Linux runtime is not yet wired",
        )


def _artifact_size(workspace: Path, manifest: Manifest) -> str:
    if manifest.kind == "build":
        image = workspace / "artifacts" / manifest.label / "Image"
    else:
        image = Path(manifest.paths.get("image_host", ""))
    return str(image.stat().st_size) if image.is_file() else "-"


def summarize_cache(workspace: Path) -> list[str]:
    builds = cache.list_manifests(workspace, "build")
    rootfs = cache.list_manifests(workspace, "rootfs")
    if not builds and not rootfs:
        return ["(cache empty)"]
    lines = ["kind    label  version  arch  size  created"]
    for m in [*builds, *rootfs]:
        mp = cache.manifest_path(workspace, m.kind, m.label)
        created = datetime.fromtimestamp(mp.stat().st_mtime, tz=UTC).date().isoformat()
        lines.append(f"{m.kind}  {m.label}  {m.version or '-'}  {m.arch}  {_artifact_size(workspace, m)}  {created}")
    return lines


def cmd_list(workspace: Path) -> int:
    for line in summarize_cache(workspace):
        logger.info(line)
    return 0


def cmd_clean(container: ContainerService, workspace: Path, *, label: str | None, clean_all: bool) -> int:
    if clean_all:
        targets = [*cache.list_manifests(workspace, "build"), *cache.list_manifests(workspace, "rootfs")]
    else:
        kind = next((k for k in ("build", "rootfs") if cache.manifest_exists(workspace, k, label or "")), None)
        if kind is None:
            raise CacheError(f"no cached artifact labelled {label!r}", remedy="run `start_kgdb --list`")
        targets = [cache.load_manifest(workspace, kind, label or "")]
    for m in targets:
        cache.remove_cached(container, workspace, m)
        logger.info(f"removed {m.kind} {m.label}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="start_kgdb")
    parser.add_argument("--config", "-c", default="")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--force-rebuild", action="store_true")
    parser.add_argument("--adopt", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--clean", default="")
    parser.add_argument("--clean-all", action="store_true")
    parser.add_argument("--use", default="")
    parser.add_argument("--rootfs", default="")
    args = parser.parse_args(argv)
    try:
        workspace = Path.cwd()
        if args.list:
            return cmd_list(workspace)
        settings = load_settings(
            workspace / "configs" / "system.ini",
            workspace / "configs" / "user.ini",
            custom_ini=Path(args.config) if args.config else None,
        )
        client = docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
        container = ContainerService(client)
        if args.clean or args.clean_all:
            return cmd_clean(container, workspace, label=args.clean or None, clean_all=args.clean_all)
        if args.use:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            session.start("LIKE-DBG")
            panes = session.open_debug_layout()
            return cmd_use(
                container,
                session,
                workspace,
                custom_ini=Path(args.config) if args.config else None,
                label=args.use,
                rootfs_label=args.rootfs or None,
                panes=panes,
            )
        # --adopt and the default run both need the recipes (and the network/hash work):
        version = resolve_version(settings.kernel_dl)
        br = make_build_recipe(settings, version=version, workspace=workspace, fragments=list(_FRAGMENTS))
        rr = make_rootfs_recipe(settings)
        if args.force_rebuild:
            cache.manifest_path(workspace, "build", br.label).unlink(missing_ok=True)
        if args.adopt:
            label = adopt_legacy_build(container, workspace=workspace, recipe=br)
            logger.info(f"adopted legacy build as {label}")
            return 0
        if not os.getenv("TMUX"):
            logger.error("Not running inside a TMUX session. Start tmux first.")
            return 2
        host = HostProfile.detect(settings, workspace)
        require_volume_mode(host)
        session = Session("LIKE-DBG")
        session.start("LIKE-DBG")
        panes = session.open_debug_layout()
        ctx = PipelineContext(settings=settings, host=host, build_label=br.label, rootfs_label=rr.label)
        pipeline = build_pipeline(
            container,
            session,
            workspace=workspace,
            kernel_volume="likedbg_ksrc",
            dl_dir=workspace / "kernels",
            debugger_image="like_debugger:latest",
            ext=settings.debugger.ext,
            panes=panes,
            build_recipe=br,
            rootfs_recipe=rr,
        )
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
