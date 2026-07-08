"""Top-level assembly: compose the pipeline + launchers + tmux session into one command."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shlex
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

from likedbg import cache
from likedbg import docker_env
from likedbg import guest
from likedbg import images
from likedbg import logsetup
from likedbg import modules
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
from likedbg.constants import EXPLOIT_MOUNT
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import MUSL_IMAGE
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
from likedbg.errors import ModuleError
from likedbg.errors import SessionError
from likedbg.exploit import run_exploit
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import compile_exploit
from likedbg.foreign import console_upload
from likedbg.foreign import resolve_foreign
from likedbg.foreign import resolve_input_path
from likedbg.host_profile import HostProfile
from likedbg.launchers import gdb_pane_command
from likedbg.modules import stage_module
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
from likedbg.stages.foreign import ForeignAdoptStage
from likedbg.stages.foreign import ForeignRepackStage
from likedbg.stages.module_build import ModuleBuildStage
from likedbg.stages.profile_verification import ProfileVerificationStage
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.unpack import UnpackStage
from likedbg.toolchain import resolve_toolchain

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


def _make_pane_launchers(
    session: Session,
    host: HostProfile,
    *,
    workspace: Path,
    debugger_image: str,
    gdb_mount_source: str,
    recorder: RunRecorder | None,
    exploit_share: Path | None = None,
) -> tuple[Callable[[str], None], Callable[[list[str]], None]]:
    """Wire the debuggee/debugger tmux panes + session-restart options for a pipeline run.

    Shared by build_pipeline / build_use_pipeline / build_foreign_pipeline, which differ only
    in how `gdb_mount_source` is sourced.
    """
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
            exploit_share=exploit_share,
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

    return launch_debuggee, run_gdb


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
    exploit_share: Path | None = None,
) -> Pipeline:
    gdb_mount_source = cache.locations(
        build_recipe.label,
        arch=build_recipe.arch,
        storage_mode=host.storage_mode,
        workspace=workspace,
        volume=kernel_volume,
    ).gdb_mount_source
    launch_debuggee, run_gdb = _make_pane_launchers(
        session,
        host,
        workspace=workspace,
        debugger_image=debugger_image,
        gdb_mount_source=gdb_mount_source,
        recorder=recorder,
        exploit_share=exploit_share,
    )

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
            ModuleBuildStage(
                container,
                image=KBUILDER_IMAGE,
                workspace=workspace,
                env=build_recipe.env(),
                arch=build_recipe.arch,
                volume=kernel_volume,
            ),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image, workspace=workspace),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
                modules_gdb=(f"{EXPLOIT_MOUNT}/modules.gdb" if exploit_share is not None else None),
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
    module_env: dict[str, str],
    recorder: RunRecorder | None = None,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
    exploit_share: Path | None = None,
) -> Pipeline:
    launch_debuggee, run_gdb = _make_pane_launchers(
        session,
        host,
        workspace=workspace,
        debugger_image=debugger_image,
        gdb_mount_source=gdb_mount_source,
        recorder=recorder,
        exploit_share=exploit_share,
    )

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
            ModuleBuildStage(
                container,
                image=KBUILDER_IMAGE,
                workspace=workspace,
                env=module_env,
                arch=host.target_arch,
                volume=kernel_volume,
            ),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image, workspace=workspace),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
                modules_gdb=(f"{EXPLOIT_MOUNT}/modules.gdb" if exploit_share is not None else None),
            ),
        ]
    )


def build_foreign_pipeline(
    container: ContainerService,
    session: Session,
    *,
    host: HostProfile,
    workspace: Path,
    foreign: ForeignKernel,
    exploit: Path | None,
    qemu_extra: tuple[str, ...],
    gdb_mount_source: str,
    out_dir: Path,
    debugger_image: str,
    debuggee_image: str,
    ext: str,
    musl_image: str,
    recorder: RunRecorder | None = None,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
) -> Pipeline:
    # ADR-0010: a foreign guest has no exploit share (no guest-side delivery path) — never mount one,
    # and DebuggerStage below is left at its modules_gdb=None default (no modules.gdb to watch).
    launch_debuggee, run_gdb = _make_pane_launchers(
        session,
        host,
        workspace=workspace,
        debugger_image=debugger_image,
        gdb_mount_source=gdb_mount_source,
        recorder=recorder,
        exploit_share=None,
    )

    return Pipeline(
        [
            ForeignAdoptStage(foreign=foreign, qemu_extra=qemu_extra),
            ForeignRepackStage(container, foreign=foreign, exploit=exploit, image=musl_image, out_dir=out_dir),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image, workspace=workspace),
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
    exploit_share = (workspace / rr.effective_debuggee.share_dir) if rr.effective_debuggee.share else None
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
        module_env=dict(resolve_toolchain(use_settings.build.compiler, host.target_arch).make_vars),
        recorder=recorder,
        break_on_crash=use_settings.debugger.break_on_crash,
        crash_breakpoints=use_settings.debugger.crash_breakpoints,
        exploit_share=exploit_share,
    )
    pipeline.run(ctx)
    return 0


def cmd_foreign(
    container: ContainerService,
    session: Session,
    workspace: Path,
    *,
    scenario: Path | None,
    profile_arg: str = "",
) -> int:
    cfg0 = load_config(workspace, scenario=scenario)
    fcfg = cfg0.settings.foreign
    if not fcfg.image:
        raise ForeignError("no [foreign].image configured", remedy="set [foreign].image in your scenario")

    name = scenario.stem if scenario is not None else "foreign"
    out_dir = workspace / "artifacts" / "foreign" / name
    # musl (+ base) must exist before we can extract vmlinux / repack.
    _ensure_images(container, workspace, specs=images.foreign_prep_images())
    fk = resolve_foreign(container, fcfg, workspace, out_dir=out_dir, image=MUSL_IMAGE)

    # Inject the detected arch so HostProfile.detect / QEMU / gdb follow the foreign kernel.
    cfg, host, rr = resolve_for_run(
        workspace,
        profile_arg=profile_arg,
        scenario=scenario,
        cli_overrides={"general": {"arch": fk.arch}},
    )
    # ADR-0010: a foreign guest exposes only the serial console — no virtio-net/9p devices the
    # CTF challenge never specified, and no run.json `guest` block (which would otherwise make
    # --run/--insmod/--rmmod try to SSH to a nonexistent sshd instead of refusing cleanly).
    # Both RunRecorder.start (run.json `guest` block) and the pipeline's DebuggeeStage (QEMU argv)
    # read effective_debuggee off the RunResolution, so overriding it here fixes both at once.
    eff = rr.effective_debuggee.model_copy(update={"guest_net": False, "share": False})
    rr = dataclasses.replace(rr, effective_debuggee=eff)
    _ensure_images(container, workspace, specs=images.required_for_foreign(host))

    exploit = resolve_input_path(workspace, fcfg.exploit) if fcfg.exploit else None
    if exploit is not None and not exploit.is_file():
        raise ForeignError(f"[foreign].exploit not found: {exploit}", remedy="check the path")

    recorder = RunRecorder.start(
        workspace=workspace,
        requested_settings=cfg.settings,
        run_resolution=rr,
        host=host,
        build_label=f"foreign-{name}",
        rootfs_label="",
        profiles=rr.profiles,
    )
    logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)

    ctx = PipelineContext(
        settings=cfg.settings,
        host=host,
        effective_debuggee=rr.effective_debuggee,
        extra_boot_args=rr.extra_boot_args,
        recorder=recorder,
    )
    pipeline = build_foreign_pipeline(
        container,
        session,
        host=host,
        workspace=workspace,
        foreign=fk,
        exploit=exploit,
        qemu_extra=fcfg.qemu_extra,
        gdb_mount_source=str(fk.vmlinux.parent),
        out_dir=out_dir,
        debugger_image=DEBUGGER_IMAGE,
        debuggee_image=DEBUGGEE_IMAGE,
        ext=cfg.settings.debugger.ext,
        musl_image=MUSL_IMAGE,
        recorder=recorder,
        break_on_crash=cfg.settings.debugger.break_on_crash,
        crash_breakpoints=cfg.settings.debugger.crash_breakpoints,
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


def cmd_run(workspace: Path, *, run_id: str, exploit: str, args: str) -> int:
    p = Path(exploit)
    container = None
    if p.suffix == ".c":
        container = ContainerService(docker_env.make_client(host=docker_env.resolve_docker_host(env=os.environ)))
        _ensure_images(container, workspace, specs=images.foreign_prep_images())
    return run_exploit(workspace, run_id, p, args, container=container)


def _guest_endpoint(workspace: Path, run_dir: Path, g: dict[str, Any]) -> guest.GuestEndpoint:
    rootfs_label = json.loads((run_dir / "run.json").read_text()).get("rootfs_label", "")
    key = cache.load_manifest(workspace, "rootfs", rootfs_label).paths.get("ssh_key", "")
    if not key:
        raise ModuleError("rootfs has no recorded SSH key", remedy="rebuild the rootfs")
    return guest.GuestEndpoint(host=str(g["ssh_host"]), port=int(g["ssh_port"]), key=Path(key))


def cmd_insmod(workspace: Path, *, run_id: str, path: str, args: str, force_unload: bool) -> int:
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    run_json = json.loads((run_dir / "run.json").read_text())
    g = run_json.get("guest")
    if not g:
        raise ModuleError("this run has no guest endpoint", remedy="boot with guest_net enabled")
    ep = _guest_endpoint(workspace, run_dir, g)
    share_dir = (workspace / g["share_dir"]).resolve()
    out_dir = share_dir / "modules"

    # build context (kernel tree + toolchain env) — reads the run's build label + host profile + config.
    build_label = run_json.get("build_label", "")
    host_json = json.loads((run_dir / "host.json").read_text())
    arch = host_json["target_arch"]
    storage_mode = host_json.get("storage_mode", "volume")
    compiler = load_config(workspace).settings.build.compiler
    env = dict(resolve_toolchain(compiler, arch).make_vars)
    loc = cache.locations(build_label, arch=arch, storage_mode=storage_mode, workspace=workspace)
    container = ContainerService(docker_env.make_client(host=docker_env.resolve_docker_host(env=os.environ)))

    # resolve the entries to stage (a PATH, else all configured custom_modules)
    if path:
        p = Path(path)
        entries = [p if p.is_absolute() else workspace / p]
    else:
        entries = [workspace / rel for rel in load_config(workspace).settings.build.custom_modules]
    if not entries:
        raise ModuleError("nothing to load", remedy="set custom_modules or pass a module path")

    kos = [
        stage_module(
            container,
            entry=e,
            out_dir=out_dir,
            kernel_root=loc.kernel_root,
            mount_source=loc.gdb_mount_source,
            env=env,
            image=KBUILDER_IMAGE,
            volume=KERNEL_VOLUME,
            kernel_label=build_label,
        )
        for e in entries
    ]
    if not guest.wait_ready(ep):
        raise ModuleError(
            f"guest not reachable at {ep.host}:{ep.port}",
            remedy="is a start_kgdb session booted and continued past start_kernel?",
        )
    for ko in kos:
        name = modules.module_name(container, ko, image=KBUILDER_IMAGE)
        res = modules.load(
            ep,
            ko,
            name=name,
            share_dir=share_dir,
            share_mount=g["share_mount"],
            args=args,
            reload=True,
            force_unload=force_unload,
        )
        # A2: read runtime section addresses from the guest and log a lifecycle `load` event.
        secs_raw = guest.run(
            ep,
            f"for s in /sys/module/{name}/sections/.*; do echo $(basename $s) $(cat $s); done",
        ).stdout
        secs = []
        for ln in secs_raw.replace("\r\n", "\n").split("\n"):
            f = ln.split()
            if len(f) == 2 and f[0].startswith("."):
                secs.append((f[0], f[1]))
        text = dict(secs).get(".text")
        modules_gdb = share_dir / "modules.gdb"
        if text:
            others = " ".join(f"{s} {a}" for s, a in secs if s != ".text")
            modules_gdb.parent.mkdir(parents=True, exist_ok=True)
            with modules_gdb.open("a") as fh:
                fh.write(f"load {name} {EXPLOIT_MOUNT}/modules/{ko.name} {text} {others}\n".rstrip() + "\n")
            note = f"symbols will load at your next gdb stop (or `source {EXPLOIT_MOUNT}/modules.gdb`)"
        else:
            note = f"no .text section read; add-symbol-file {g['share_mount']}/modules/{ko.name} manually"
        print(f"[likedbg] loaded {name} (rc={res.rc}) — {g['share_mount']}/modules/{ko.name}; {note}")
    return 0


def _console_tail_reader(console_path: Path, *, timeout: float = 10.0, poll: float = 0.5) -> Callable[[], str]:
    """Build a `read_console` callable for `foreign.console_upload`: each call blocks (up to
    `timeout`) polling `console_path` for newly-appended bytes since the previous call, and
    returns them CRLF-normalized (the serial console writes \\r\\n)."""
    pos = 0

    def read_console() -> str:
        nonlocal pos
        deadline = timeout
        while True:
            if console_path.is_file():
                with console_path.open("rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                if chunk:
                    pos += len(chunk)
                    return chunk.decode(errors="replace").replace("\r\n", "\n")
            if deadline <= 0:
                return ""
            time.sleep(poll)
            deadline -= poll

    return read_console


def cmd_upload(workspace: Path, *, run_id: str, file: str) -> int:
    """Live exploit delivery over the serial console — see foreign.console_upload. Optional
    fallback to repack; NEVER runs the uploaded file (delivery only)."""
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    session = Session("LIKE-DBG")
    pane = session.get_option("@likedbg_debuggee_pane")
    if not pane:
        raise ForeignError(
            "no live Debuggee pane recorded for this tmux session",
            remedy="boot a session first (`start_kgdb`), then retry --upload",
        )
    f = Path(file)
    if f.suffix == ".c":
        host_json = json.loads((run_dir / "host.json").read_text())
        container = ContainerService(docker_env.make_client(host=docker_env.resolve_docker_host(env=os.environ)))
        _ensure_images(container, workspace, specs=images.foreign_prep_images())
        f = compile_exploit(
            container, src=f, arch=host_json["target_arch"], out=run_dir / "exploit" / f.stem, image=MUSL_IMAGE
        )
    console_upload(
        session,
        pane,
        f,
        read_console=_console_tail_reader(run_dir / "logs" / "console.raw"),
    )
    return 0


def cmd_rmmod(workspace: Path, *, run_id: str, name: str, force_unload: bool) -> int:
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    g = json.loads((run_dir / "run.json").read_text()).get("guest")
    if not g:
        raise ModuleError("this run has no guest endpoint", remedy="boot with guest_net enabled")
    ep = _guest_endpoint(workspace, run_dir, g)
    if not guest.wait_ready(ep):
        raise ModuleError(f"guest not reachable at {ep.host}:{ep.port}", remedy="boot + continue the session")
    res = modules.unload(ep, name, force=force_unload)
    share_dir = (workspace / g["share_dir"]).resolve()
    modules_gdb = share_dir / "modules.gdb"
    if modules_gdb.exists() or share_dir.exists():
        modules_gdb.parent.mkdir(parents=True, exist_ok=True)
        with modules_gdb.open("a") as fh:
            fh.write(f"unload {name}\n")
    print(f"[likedbg] rmmod {name} (rc={res.rc}); symbols removed at your next gdb stop")
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
    parser.add_argument("--run", default="", metavar="EXPLOIT-PATH")
    parser.add_argument("--upload", default="", metavar="EXPLOIT-PATH")
    parser.add_argument("--args", default="")
    parser.add_argument("--run-id", default="latest")
    parser.add_argument("--insmod", default="", metavar="MODULE")
    parser.add_argument("--rmmod", default="")
    parser.add_argument("--force-unload", action="store_true")
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
        if args.run:
            return cmd_run(workspace, run_id=args.run_id, exploit=args.run, args=args.args)
        if args.upload:
            return cmd_upload(workspace, run_id=args.run_id, file=args.upload)
        if args.insmod:
            return cmd_insmod(
                workspace, run_id=args.run_id, path=args.insmod, args=args.args, force_unload=args.force_unload
            )
        if args.rmmod:
            return cmd_rmmod(workspace, run_id=args.run_id, name=args.rmmod, force_unload=args.force_unload)
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
        if cfg.settings.foreign.image:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            session.start("LIKE-DBG")
            return cmd_foreign(
                container,
                session,
                workspace,
                scenario=_scenario_path(workspace, args.config),
                profile_arg=args.profile,
            )
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
        exploit_share = (workspace / run_res.effective_debuggee.share_dir) if run_res.effective_debuggee.share else None
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
            exploit_share=exploit_share,
        )
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
