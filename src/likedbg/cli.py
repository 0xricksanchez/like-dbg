"""Top-level assembly: compose the pipeline + launchers + tmux session into one command."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import urllib.request
from datetime import UTC
from datetime import datetime
from pathlib import Path

from loguru import logger

from likedbg import cache
from likedbg import docker_env
from likedbg import images
from likedbg import logsetup
from likedbg.adopt import adopt_legacy_build
from likedbg.adopt import adopt_legacy_rootfs
from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import RootfsRecipe
from likedbg.cache import build_recipe as make_build_recipe
from likedbg.cache import rootfs_recipe as make_rootfs_recipe
from likedbg.config import ConfigResolution
from likedbg.config import load_config
from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGEE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import ROOTFS_IMAGE
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.crash.analyze import analyze_run
from likedbg.debug_profiles import RunResolution
from likedbg.debug_profiles import parse_profile_names
from likedbg.debug_profiles import resolve_run
from likedbg.errors import CacheError
from likedbg.errors import HostCapabilityError
from likedbg.errors import LikeDbgError
from likedbg.errors import SessionError
from likedbg.host_profile import HostProfile
from likedbg.launchers import gdb_pane_command
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext
from likedbg.run_artifacts import RunRecorder
from likedbg.session import Session
from likedbg.stages.build import BuildStage
from likedbg.stages.debuggee import DebuggeeStage
from likedbg.stages.debugger import DebuggerStage
from likedbg.stages.download import DownloadStage
from likedbg.stages.download import resolve_version
from likedbg.stages.export import ArtifactExporter
from likedbg.stages.profile_verification import ProfileVerificationStage
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.unpack import UnpackStage

_FRAGMENTS = (
    "configs/fragments/debug.config",
    "configs/fragments/no-kaslr.config",
    "configs/fragments/generic.config",
)

_SESSION_STATE_OPTIONS = (
    "@likedbg_restart_in_progress",
    "@likedbg_debuggee_cmd",
    "@likedbg_debugger_cmd",
    "@likedbg_debuggee_pane",
    "@likedbg_debugger_pane",
    "@likedbg_debuggee_pane_log",
)


def _fetch(url: str, dest: Path) -> None:
    urllib.request.urlretrieve(url, str(dest))  # noqa: S310


def _scenario_path(workspace: Path, arg: str) -> Path | None:
    """Resolve a -c argument to a scenario Path, or None if arg is empty."""
    if not arg:
        return None
    p = Path(arg)
    if "/" in arg or arg.endswith(".toml"):
        return p
    return workspace / "configs" / "scenarios" / f"{arg}.toml"


def resolve_for_run(
    workspace: Path,
    *,
    profile_arg: str,
    scenario: Path | None,
    cli_overrides: dict[str, dict[str, str]] | None,
) -> tuple[ConfigResolution, HostProfile, RunResolution]:
    """Testable prelude: load_config -> detect host -> resolve run profiles.

    Errors here (unknown profile, bad config) happen BEFORE any run dir is created.
    Callers must create the RunRecorder only after this returns successfully.
    """
    cfg = load_config(workspace, scenario=scenario, cli_overrides=cli_overrides)
    host = HostProfile.detect(cfg.settings, workspace)
    names = parse_profile_names(profile_arg) if profile_arg else cfg.settings.debugging.profiles
    rr = resolve_run(profile_names=names, config=cfg, host=host, workspace=workspace)
    for w in rr.profile_warnings:
        logger.warning(w)
    for n in (*rr.runtime_overrides, *rr.runtime_notes):
        logger.info(n)
    logger.info(f"resolved profiles: {', '.join(rr.profiles.names)}")
    return cfg, host, rr


def _provenance_nested(prov: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    """Convert flat provenance dict with (section, key) tuples to nested {section: {key: layer}}.

    # NOTE: mirror of run_artifacts._provenance_json — import cycle prevents hoisting.
    """
    out: dict[str, dict[str, str]] = {}
    for (section, key), layer in prov.items():
        out.setdefault(section, {})[key] = layer
    return out


def explain_config(
    workspace: Path,
    *,
    profile_arg: str,
    scenario: Path | None,
    fmt: str,
) -> str:
    """Dry-run inspection: resolve profiles and render config summary without touching Docker/tmux/run-dirs."""
    _cfg, _host, rr = resolve_for_run(workspace, profile_arg=profile_arg, scenario=scenario, cli_overrides=None)
    eff = rr.effective_debuggee
    payload: dict[str, object] = {
        "target_arch": rr.target_arch,
        "profiles": {
            "requested": list(rr.profiles.names),
            "base": rr.profiles.base,
            "resolved": list(rr.profiles.names),
            "implied_by": {k: list(v) for k, v in rr.implied_by.items()},
        },
        "fragments": list(rr.fragments),
        "effective_debuggee": eff.model_dump(),
        "provenance": _provenance_nested(rr.provenance),
        "runtime_notes": list(rr.runtime_notes) + list(rr.runtime_overrides),
        "warnings": list(rr.profile_warnings),
        "extra_boot_args": list(rr.extra_boot_args),
        "expected_config": [
            {
                "symbol": e.symbol,
                "value": e.value,
                "severity": e.severity,
                "arch": list(e.arch) if e.arch is not None else None,
                "kernel_min": e.kernel_min,
                "kernel_max": e.kernel_max,
                "status": "pending-build",
            }
            for e in rr.profiles.expected_config
        ],
    }
    if fmt == "json":
        return json.dumps({"schema_version": 1, **payload}, indent=2, sort_keys=True)
    profiles_info = payload["profiles"]
    assert isinstance(profiles_info, dict)
    resolved = profiles_info["resolved"]
    assert isinstance(resolved, list)
    base = profiles_info["base"]
    fragments = payload["fragments"]
    assert isinstance(fragments, list)
    warnings = payload["warnings"]
    assert isinstance(warnings, list)
    expected = payload["expected_config"]
    assert isinstance(expected, list)
    lines = [
        f"target arch: {payload['target_arch']}",
        f"profiles:    {', '.join(str(p) for p in resolved)} (base {base})",
        "fragments:",
        *[f"  {f}" for f in fragments],
        "warnings:",
        *(([f"  {w}" for w in warnings]) if warnings else ["  (none)"]),
        "expected config (pending build):",
        *[f"  {e['symbol']}={e['value']} [{e['severity']}]" for e in expected],
    ]
    return "\n".join(lines)


def build_pipeline(
    container: ContainerService,
    session: Session,
    *,
    host: HostProfile,
    chown_to: tuple[int, int] | None = None,
    workspace: Path,
    kernel_volume: str,
    dl_dir: Path,
    debugger_image: str,
    debuggee_image: str,
    ext: str,
    build_recipe: BuildRecipe,
    rootfs_recipe: RootfsRecipe,
    patch_dirs: tuple[str, ...] = (),
    recorder: RunRecorder | None = None,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
) -> Pipeline:
    base_pane = session.current_pane_id()
    debuggee_pane: str | None = None

    for opt in _SESSION_STATE_OPTIONS:
        session.unset_option(opt)
    session.set_option("@likedbg_workspace", str(workspace))
    session.set_option("@likedbg_base_pane_id", base_pane)

    def launch_debuggee(cmd: str) -> None:
        nonlocal debuggee_pane
        session.set_option("@likedbg_debuggee_cmd", cmd)
        debuggee_pane = session.run_in_new_pane(target=base_pane, direction="h", percent=66, cmd=cmd)
        session.set_option("@likedbg_debuggee_pane", debuggee_pane)
        if recorder is not None:
            session.set_option("@likedbg_debuggee_pane_log", str(recorder.debuggee_pane_log))
            try:
                session.pipe_pane(pane=debuggee_pane, output=recorder.debuggee_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debuggee: {exc}")

    def run_gdb(args: list[str]) -> None:
        if debuggee_pane is None:
            raise RuntimeError("debuggee pane has not been launched")
        loc = cache.locations(
            build_recipe.label,
            arch=build_recipe.arch,
            storage_mode=host.storage_mode,
            workspace=workspace,
            volume=kernel_volume,
        )
        cmd = gdb_pane_command(
            args,
            image=debugger_image,
            mount_source=loc.gdb_mount_source,
            network_mode=host.network_mode,
            crash_drop=recorder.crash_dir if recorder is not None else None,
        )
        session.set_option("@likedbg_debugger_cmd", cmd)
        debugger_pane = session.run_in_new_pane(
            target=debuggee_pane,
            direction="v",
            percent=50,
            cmd=cmd,
        )
        session.set_option("@likedbg_debugger_pane", debugger_pane)
        if recorder is not None:
            try:
                session.pipe_pane(pane=debugger_pane, output=recorder.debugger_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debugger: {exc}")

    return Pipeline(
        [
            DownloadStage(_fetch, dl_dir=dl_dir),
            UnpackStage(container, kernel_volume=kernel_volume, workspace=workspace),
            BuildStage(
                container,
                recipe=build_recipe,
                kbuilder_image=KBUILDER_IMAGE,
                workspace=workspace,
                kernel_volume=kernel_volume,
                chown_to=chown_to,
                patch_dirs=patch_dirs,
            ),
            ProfileVerificationStage(container, workspace=workspace, kernel_volume=kernel_volume),
            RootfsStage(
                container,
                recipe=rootfs_recipe,
                rootfs_image=ROOTFS_IMAGE,
                workspace=workspace,
            ),
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
            ),
        ]
    )


def build_use_pipeline(
    container: ContainerService,
    session: Session,
    *,
    host: HostProfile,
    workspace: Path,
    kernel_volume: str,
    debugger_image: str,
    debuggee_image: str,
    ext: str,
    gdb_mount_source: str,
    rootfs_recipe: RootfsRecipe,
    recorder: RunRecorder | None = None,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
) -> Pipeline:
    base_pane = session.current_pane_id()
    debuggee_pane: str | None = None

    for opt in _SESSION_STATE_OPTIONS:
        session.unset_option(opt)
    session.set_option("@likedbg_workspace", str(workspace))
    session.set_option("@likedbg_base_pane_id", base_pane)

    def launch_debuggee(cmd: str) -> None:
        nonlocal debuggee_pane
        session.set_option("@likedbg_debuggee_cmd", cmd)
        debuggee_pane = session.run_in_new_pane(target=base_pane, direction="h", percent=66, cmd=cmd)
        session.set_option("@likedbg_debuggee_pane", debuggee_pane)
        if recorder is not None:
            session.set_option("@likedbg_debuggee_pane_log", str(recorder.debuggee_pane_log))
            try:
                session.pipe_pane(pane=debuggee_pane, output=recorder.debuggee_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debuggee: {exc}")

    def run_gdb(args: list[str]) -> None:
        if debuggee_pane is None:
            raise RuntimeError("debuggee pane has not been launched")
        cmd = gdb_pane_command(
            args,
            image=debugger_image,
            mount_source=gdb_mount_source,
            network_mode=host.network_mode,
            crash_drop=recorder.crash_dir if recorder is not None else None,
        )
        session.set_option("@likedbg_debugger_cmd", cmd)
        debugger_pane = session.run_in_new_pane(
            target=debuggee_pane,
            direction="v",
            percent=50,
            cmd=cmd,
        )
        session.set_option("@likedbg_debugger_pane", debugger_pane)
        if recorder is not None:
            try:
                session.pipe_pane(pane=debugger_pane, output=recorder.debugger_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debugger: {exc}")

    return Pipeline(
        [
            ProfileVerificationStage(container, workspace=workspace, kernel_volume=kernel_volume),
            RootfsStage(
                container,
                recipe=rootfs_recipe,
                rootfs_image=ROOTFS_IMAGE,
                workspace=workspace,
            ),
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
            ),
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
    profile_arg: str = "",
) -> int:
    if not cache.manifest_exists(workspace, "build", label):
        raise CacheError(f"no cached build labelled {label!r}", remedy="run `start_kgdb --list`")
    bm = cache.load_manifest(workspace, "build", label)
    # Build identity (arch) is authoritative; reload config with the arch override so the
    # host profile / QEMU follow the cached build, keeping runtime+debugger prefs from config.
    scenario = _scenario_path(workspace, str(custom_ini) if custom_ini is not None else "")
    cfg, host, rr = resolve_for_run(
        workspace,
        profile_arg=profile_arg,
        scenario=scenario,
        cli_overrides={"general": {"arch": bm.arch}},
    )
    use_settings = cfg.settings
    _ensure_images(container, workspace, specs=images.required_for_use(host))
    rr_recipe = make_rootfs_recipe(use_settings, arch=host.target_arch, workspace=workspace)
    rlabel = rootfs_label or rr_recipe.label
    if (
        rootfs_label is not None
        and rootfs_label != rr_recipe.label
        and not cache.manifest_exists(workspace, "rootfs", rlabel)
    ):
        raise CacheError(
            f"no cached rootfs labelled {rlabel!r}",
            remedy="omit --rootfs to build the active rootfs, or run `start_kgdb --list`",
        )
    recorder = RunRecorder.start(
        workspace=workspace,
        requested_settings=use_settings,
        run_resolution=rr,
        host=host,
        build_label=label,
        rootfs_label=rlabel,
        profiles=rr.profiles,
    )
    logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)
    kernel_image_path = bm.paths["image_host"] if bm.storage_mode != "volume" else bm.paths["image_in_tree"]
    ctx = PipelineContext(
        settings=use_settings,
        host=host,
        kernel_root=Path(bm.paths["kernel_root"]),
        vmlinux=Path(bm.paths["gdb_vmlinux"]),
        kernel_image=Path(kernel_image_path),
        build_label=label,
        rootfs_label=rlabel,
        run_resolution=rr,
        effective_debuggee=rr.effective_debuggee,
        extra_boot_args=rr.extra_boot_args,
        recorder=recorder,
    )
    pipeline = build_use_pipeline(
        container,
        session,
        host=host,
        workspace=workspace,
        kernel_volume=KERNEL_VOLUME,
        debugger_image=DEBUGGER_IMAGE,
        debuggee_image=DEBUGGEE_IMAGE,
        ext=use_settings.debugger.ext,
        gdb_mount_source=bm.paths["gdb_mount_source"],
        rootfs_recipe=rr_recipe,
        recorder=recorder,
        break_on_crash=use_settings.debugger.break_on_crash,
        crash_breakpoints=use_settings.debugger.crash_breakpoints,
    )
    pipeline.run(ctx)
    return 0


def _require_volume_for_adopt(host: HostProfile) -> None:
    if host.storage_mode != "volume":
        raise HostCapabilityError(
            "--adopt migrates the legacy in-volume tree and is volume-mode only",
            remedy="bind/Linux builds fresh — just run start_kgdb",
        )


def _ensure_images(container: ContainerService, workspace: Path, *, specs: tuple[images.ImageSpec, ...]) -> None:
    for tag in images.ensure_current(container, workspace, specs):
        logger.warning(f"image {tag} looks stale (build inputs changed); run `start_kgdb --build-images` to refresh")


def _volume_build_size(container: ContainerService, manifest: Manifest, *, volume: str = KERNEL_VOLUME) -> str | None:
    kernel_root = manifest.paths.get("kernel_root")
    if manifest.storage_mode != "volume" or not kernel_root:
        return None
    try:
        c = container.run_detached(
            BASE_IMAGE,
            volumes={volume: {"bind": VOLUME_MOUNT, "mode": "ro"}},
            detach=True,
            tty=True,
        )
        try:
            out = container.exec(c, f"du -sb {shlex.quote(kernel_root)}").output.strip()
        finally:
            container.stop(c)
        size = int(out.split()[0])
    except Exception:  # noqa: BLE001 - `--list` should remain best-effort if Docker/du is unavailable.
        return None
    return str(size)


def _artifact_size(workspace: Path, manifest: Manifest, *, container: ContainerService | None = None) -> str:
    if manifest.kind == "build":
        if container is not None:
            volume_size = _volume_build_size(container, manifest)
            if volume_size is not None:
                return volume_size
        candidates = [Path(manifest.paths.get("image_host", "")), workspace / "artifacts" / manifest.label / "Image"]
    else:
        candidates = [Path(manifest.paths.get("image_host", ""))]
    image = next((candidate for candidate in candidates if candidate.is_file()), None)
    return str(image.stat().st_size) if image is not None else "-"


def summarize_cache(workspace: Path, *, container: ContainerService | None = None) -> list[str]:
    builds = cache.list_manifests(workspace, "build")
    rootfs = cache.list_manifests(workspace, "rootfs")
    if not builds and not rootfs:
        return ["(cache empty)"]
    lines = ["kind    label  version  arch  size  created"]
    for m in [*builds, *rootfs]:
        mp = cache.manifest_path(workspace, m.kind, m.label)
        created = datetime.fromtimestamp(mp.stat().st_mtime, tz=UTC).date().isoformat()
        lines.append(
            f"{m.kind}  {m.label}  {m.version or '-'}  {m.arch}  "
            f"{_artifact_size(workspace, m, container=container)}  {created}"
        )
    return lines


def cmd_list(workspace: Path, *, container: ContainerService | None = None) -> int:
    for line in summarize_cache(workspace, container=container):
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


def _missing_restart_state(name: str) -> SessionError:
    return SessionError(
        f"missing {name}; cannot restart Debuggee",
        remedy="start a fresh Debugging session with `uv run ./start_kgdb`",
    )


def cmd_restart_debuggee(session: Session) -> int:
    if session.get_option("@likedbg_restart_in_progress") == "1":
        raise SessionError("LIKE-DBG restart already in progress")
    session.set_option("@likedbg_restart_in_progress", "1")
    try:
        workspace = session.get_option("@likedbg_workspace")
        cmd = session.get_option("@likedbg_debuggee_cmd")
        debuggee_pane = session.get_option("@likedbg_debuggee_pane")
        base_pane = session.get_option("@likedbg_base_pane_id")
        if not workspace:
            raise _missing_restart_state("@likedbg_workspace")
        if not cmd:
            raise _missing_restart_state("@likedbg_debuggee_cmd")
        active_pane = session.current_pane_id()
        if debuggee_pane and session.pane_exists(debuggee_pane):
            session.respawn_pane(pane=debuggee_pane, cmd=cmd)
        else:
            if not base_pane:
                raise _missing_restart_state("@likedbg_base_pane_id")
            if not session.pane_exists(base_pane):
                raise SessionError(
                    f"stored base pane {base_pane} is gone; cannot recreate Debuggee pane",
                    remedy="start a fresh Debugging session with `uv run ./start_kgdb`",
                )
            debuggee_pane = session.run_in_new_pane(target=base_pane, direction="h", percent=66, cmd=cmd)
            session.set_option("@likedbg_debuggee_pane", debuggee_pane)
        pane_log = session.get_option("@likedbg_debuggee_pane_log")
        if pane_log and debuggee_pane:
            try:
                session.pipe_pane(pane=debuggee_pane, output=Path(pane_log))
            except LikeDbgError:
                pass
        if active_pane and session.pane_exists(active_pane):
            session.select_pane(active_pane)
        try:
            session.display_message(
                "LIKE-DBG Debuggee restarted; in GDB run likedbg-reconnect, not target remote localhost"
            )
        except LikeDbgError:
            pass
        return 0
    finally:
        session.unset_option("@likedbg_restart_in_progress")


def cmd_analyze_crash(workspace: Path, *, run_id: str) -> int:
    """Pure-host crash analysis: resolve a run dir, run analyze_run, print a summary.

    Docker/tmux-free — safe to dispatch before any container/session setup.
    """
    runs = workspace / "artifacts" / "runs"
    run_dir = (runs / "latest") if run_id == "latest" else (runs / run_id)
    run_dir = run_dir.resolve() if run_dir.is_symlink() else run_dir
    report = analyze_run(run_dir)
    if report is None:
        logger.info("no crash detected")
        print("no crash detected")
        return 0
    prim = report.events[report.primary] if report.primary is not None else report.events[0]
    print(f"crash: {prim.kind} — {prim.title}")
    print(f"  report: {run_dir / 'crash.md'}")
    print(f"  json:   {run_dir / 'crash.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="start_kgdb")
    parser.add_argument("--config", "-c", default="")
    parser.add_argument("--profile", default="")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--force-rebuild", action="store_true")
    parser.add_argument("--adopt", action="store_true")
    parser.add_argument("--adopt-rootfs", nargs="?", const="", default=None, metavar="SOURCE")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--clean", default="")
    parser.add_argument("--clean-all", action="store_true")
    parser.add_argument("--use", default="")
    parser.add_argument("--rootfs", default="")
    parser.add_argument("--build-images", action="store_true")
    parser.add_argument("--restart-debuggee", action="store_true")
    parser.add_argument("--explain-config", nargs="?", const="text", default=None, choices=["text", "json"])
    parser.add_argument("--analyze-crash", nargs="?", const="latest", default=None, metavar="RUN-ID")
    args = parser.parse_args(argv)
    logsetup.configure_stderr(verbose=args.verbose)
    try:
        workspace = Path.cwd()
        if args.explain_config is not None:
            print(
                explain_config(
                    workspace,
                    profile_arg=args.profile,
                    scenario=_scenario_path(workspace, args.config),
                    fmt=args.explain_config,
                )
            )
            return 0
        if args.analyze_crash is not None:
            return cmd_analyze_crash(workspace, run_id=args.analyze_crash)
        if args.restart_debuggee:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            try:
                return cmd_restart_debuggee(session)
            except LikeDbgError as exc:
                logger.error(str(exc))
                try:
                    session.display_message(f"LIKE-DBG restart failed: {exc.message}")
                except LikeDbgError:
                    pass
                return 1
        if args.list:
            try:
                list_container = ContainerService(
                    docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
                )
            except Exception:  # noqa: BLE001 - fall back to host-visible sizes when Docker is unavailable.
                list_container = None
            return cmd_list(workspace, container=list_container)
        # Early paths that don't need the full TOML flow: --build-images, --clean*, --adopt-rootfs
        cfg = load_config(workspace, scenario=_scenario_path(workspace, args.config))
        rr_settings = make_rootfs_recipe(cfg.settings, workspace=workspace)
        if args.adopt_rootfs is not None:
            source = Path(args.adopt_rootfs) if args.adopt_rootfs else None
            label = adopt_legacy_rootfs(workspace=workspace, recipe=rr_settings, source=source)
            logger.info(f"adopted legacy rootfs as {label}")
            return 0
        client = docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
        container = ContainerService(client)
        if args.build_images:
            images.build_images(container, workspace)
            return 0
        if args.clean or args.clean_all:
            return cmd_clean(container, workspace, label=args.clean or None, clean_all=args.clean_all)
        if args.use:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            session.start("LIKE-DBG")
            return cmd_use(
                container,
                session,
                workspace,
                custom_ini=Path(args.config) if args.config else None,
                label=args.use,
                rootfs_label=args.rootfs or None,
                profile_arg=args.profile,
            )
        # Default run: full TOML flow with profile resolution.
        scenario = _scenario_path(workspace, args.config)
        cfg, host, run_res = resolve_for_run(
            workspace,
            profile_arg=args.profile,
            scenario=scenario,
            cli_overrides=None,
        )
        version = resolve_version(cfg.settings.source)
        br = make_build_recipe(
            cfg.settings,
            version=version,
            arch=host.target_arch,
            workspace=workspace,
            fragments=list(run_res.fragments) + list(cfg.settings.build.extra_fragments),
            patch_dirs=cfg.settings.build.patch_dirs,
        )
        rr_recipe = make_rootfs_recipe(cfg.settings, arch=host.target_arch, workspace=workspace)
        if args.force_rebuild:
            cache.manifest_path(workspace, "build", br.label).unlink(missing_ok=True)
        if args.adopt:
            _require_volume_for_adopt(host)
            label = adopt_legacy_build(container, workspace=workspace, recipe=br)
            logger.info(f"adopted legacy build as {label}")
            return 0
        if not os.getenv("TMUX"):
            logger.error("Not running inside a TMUX session. Start tmux first.")
            return 2
        recorder = RunRecorder.start(
            workspace=workspace,
            requested_settings=cfg.settings,
            run_resolution=run_res,
            host=host,
            build_label=br.label,
            rootfs_label=rr_recipe.label,
            profiles=run_res.profiles,
        )
        logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)
        _ensure_images(container, workspace, specs=images.required_for(host))
        chown_to = (os.getuid(), os.getgid()) if host.os == "linux" and host.storage_mode == "bind" else None
        session = Session("LIKE-DBG")
        session.start("LIKE-DBG")
        ctx = PipelineContext(
            settings=cfg.settings,
            host=host,
            build_label=br.label,
            rootfs_label=rr_recipe.label,
            run_resolution=run_res,
            effective_debuggee=run_res.effective_debuggee,
            extra_boot_args=run_res.extra_boot_args,
            recorder=recorder,
        )
        pipeline = build_pipeline(
            container,
            session,
            host=host,
            chown_to=chown_to,
            workspace=workspace,
            kernel_volume=KERNEL_VOLUME,
            dl_dir=workspace / "kernels",
            debugger_image=DEBUGGER_IMAGE,
            debuggee_image=DEBUGGEE_IMAGE,
            ext=cfg.settings.debugger.ext,
            build_recipe=br,
            rootfs_recipe=rr_recipe,
            patch_dirs=cfg.settings.build.patch_dirs,
            recorder=recorder,
            break_on_crash=cfg.settings.debugger.break_on_crash,
            crash_breakpoints=cfg.settings.debugger.crash_breakpoints,
        )
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
