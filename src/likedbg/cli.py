"""Top-level assembly: compose the pipeline + launchers + tmux session into one command."""

from __future__ import annotations

import argparse
import os
import urllib.request
from pathlib import Path

from loguru import logger

from likedbg import docker_env
from likedbg.config import load_settings
from likedbg.container_service import ContainerService
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
from likedbg.stages.export import ArtifactExporter
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.unpack import UnpackStage

_FRAGMENTS = [
    "configs/fragments/debug.config",
    "configs/fragments/no-kaslr.config",
    "configs/fragments/generic.config",
]


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
) -> Pipeline:
    debuggee_pane, debugger_pane = panes

    def launch_qemu(argv: list[str]) -> None:
        session.select_pane(debuggee_pane)
        session.send_keys(qemu_pane_command(argv))

    def run_gdb(args: list[str]) -> None:
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, kernel_volume=kernel_volume))

    return Pipeline(
        [
            DownloadStage(_fetch, dl_dir=dl_dir),
            UnpackStage(container, kernel_volume=kernel_volume, workspace=workspace),
            BuildStage(
                container,
                kbuilder_image="like_kbuilder_arm64:latest",
                fragments=_FRAGMENTS,
                workspace=workspace,
                kernel_volume=kernel_volume,
            ),
            RootfsStage(container, rootfs_image="like_rootfs:latest", workspace=workspace),
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_qemu),
            DebuggerStage(ext=ext, run_gdb=run_gdb, breakpoint="start_kernel"),
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="start_kgdb")
    parser.add_argument("--config", "-c", default="")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    if not os.getenv("TMUX"):
        logger.error("Not running inside a TMUX session. Start tmux first.")
        return 2
    try:
        workspace = Path.cwd()
        settings = load_settings(
            workspace / "configs" / "system.ini",
            workspace / "configs" / "user.ini",
            custom_ini=Path(args.config) if args.config else None,
        )
        client = docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
        container = ContainerService(client)
        host = HostProfile.detect(settings, workspace)
        session = Session("LIKE-DBG")
        session.start("LIKE-DBG")
        panes = session.open_debug_layout()
        pipeline = build_pipeline(
            container,
            session,
            workspace=workspace,
            kernel_volume="likedbg_ksrc",
            dl_dir=workspace / "kernels",
            debugger_image="like_debugger:latest",
            ext=settings.debugger.ext,
            panes=panes,
        )
        ctx = PipelineContext(settings=settings, host=host)
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
