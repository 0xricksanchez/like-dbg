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
from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import RootfsRecipe
from likedbg.cache import build_recipe as make_build_recipe
from likedbg.cache import rootfs_recipe as make_rootfs_recipe
from likedbg.cache import slug
from likedbg.config import LAYER_CLI
from likedbg.config import LAYER_LOCAL
from likedbg.config import LAYER_SCENARIO
from likedbg.config import ConfigResolution
from likedbg.config import ForeignCfg
from likedbg.config import load_config
from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGEE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import EXPLOIT_MOUNT
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import LIKEDBG_ZIG_CACHE_VOLUME
from likedbg.constants import MUSL_IMAGE
from likedbg.constants import ROOTFS_IMAGE
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.crash.analyze import analyze_run
from likedbg.debug_profiles import RunResolution
from likedbg.debug_profiles import parse_profile_names
from likedbg.debug_profiles import resolve_run
from likedbg.errors import CacheError
from likedbg.errors import ConfigError
from likedbg.errors import LikeDbgError
from likedbg.errors import ModuleError
from likedbg.errors import SessionError
from likedbg.exploit import run_exploit
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import compile_exploit
from likedbg.foreign import console_upload
from likedbg.foreign import detect_arch
from likedbg.foreign import exploit_flags_for
from likedbg.foreign import resolve_foreign
from likedbg.foreign import resolve_input_path
from likedbg.gdbcmd import resolve_debuginfod_enabled
from likedbg.host_profile import HostProfile
from likedbg.launchers import gdb_pane_command
from likedbg.modules import stage_module
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext
from likedbg.ports import resolve_ports
from likedbg.run_artifacts import RunRecorder
from likedbg.run_state import guest_endpoint
from likedbg.run_state import read_run_state
from likedbg.session import Session
from likedbg.session import unique_session_name
from likedbg.stages.build import BuildStage
from likedbg.stages.cache_eviction import CacheEvictionStage
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
    "@likedbg_rerun_request",
    "@likedbg_active_run_dir",
    "@likedbg_debuggee_cmd",
    "@likedbg_debugger_cmd",
    "@likedbg_debuggee_pane",
    "@likedbg_debugger_pane",
    "@likedbg_debuggee_pane_log",
)


@dataclasses.dataclass(frozen=True)
class RerunRequest:
    kind: str
    scenario: Path | None
    profile_arg: str
    use_label: str = ""
    rootfs_label: str = ""


_RERUN_OPTION = "@likedbg_rerun_request"
_ACTIVE_RUN_DIR_OPTION = "@likedbg_active_run_dir"


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
    validate_build_gates: bool = True,
) -> tuple[ConfigResolution, HostProfile, RunResolution]:
    """Testable prelude: load_config -> detect host -> resolve run profiles.

    Errors here (unknown profile, bad config) happen BEFORE any run dir is created.
    Callers must create the RunRecorder only after this returns successfully.
    """
    cfg = load_config(workspace, scenario=scenario, cli_overrides=cli_overrides)
    host = HostProfile.detect(cfg.settings, workspace)
    names = parse_profile_names(profile_arg) if profile_arg else cfg.settings.general.profiles
    rr = resolve_run(
        profile_names=names,
        config=cfg,
        host=host,
        workspace=workspace,
        validate_build_gates=validate_build_gates,
    )
    for w in rr.profile_warnings:
        logger.warning(w)
    for n in (*rr.runtime_overrides, *rr.runtime_notes):
        logger.info(n)
    logger.info(f"resolved profiles: {', '.join(rr.profiles.names)}")
    return cfg, host, rr


def _provenance_nested(prov: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    """Convert flat provenance dict with (section, key) tuples to nested {section: {key: layer}}.

    # NOTE: mirror of run_artifacts._provenance_json (import cycle prevents hoisting).
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

    def _adopted_arch(ws: Path, f: ForeignCfg) -> str:
        if f.arch:
            return f.arch
        if f.vmlinux:
            vmlinux = resolve_input_path(ws, f.vmlinux)
            if vmlinux.is_file():
                try:
                    return detect_arch(vmlinux)
                except ForeignError:
                    pass
        return "native"

    # Build-time .config gates describe kernels LIKE-DBG built. A [foreign] scenario adopts one, so
    # cmd_foreign resolves with validate_build_gates=False; explain must agree or it reports a run
    # impossible that would in fact boot. Detected the same way cmd_foreign does: [foreign].image.
    fcfg = load_config(workspace, scenario=scenario).settings.foreign
    adopted = bool(fcfg.image)
    # cmd_foreign injects the adopted kernel's arch so the arch gates (smep/smap/fgkaslr) judge the
    # guest, not the host. Mirror it, but stay Docker-free: take [foreign].arch, else read the ELF
    # of a supplied vmlinux. With neither, explain falls back to the host arch -- the honest limit,
    # since detecting it would mean extracting a vmlinux in a container.
    overrides = {"general": {"arch": _adopted_arch(workspace, fcfg)}} if adopted else None
    cfg, _host, rr = resolve_for_run(
        workspace,
        profile_arg=profile_arg,
        scenario=scenario,
        cli_overrides=overrides,
        validate_build_gates=not adopted,
    )
    eff = rr.effective_debuggee
    payload: dict[str, object] = {
        "target_arch": rr.target_arch,
        "build_gates": "skipped" if adopted else "applied",
        "profiles": {
            "requested": list(rr.profiles.names),
            "base": rr.profiles.base,
            "resolved": list(rr.profiles.names),
            "implied_by": {k: list(v) for k, v in rr.implied_by.items()},
        },
        # rr.fragments is the profile-resolved set; extra_fragments are appended after it at build time
        # (profile fragments first, extra_fragments last, later wins on conflicting symbols).
        "fragments": list(rr.fragments),
        "extra_fragments": list(cfg.settings.build.extra_fragments),
        "patch_dirs": list(cfg.settings.build.patch_dirs),
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
    extra_fragments = payload["extra_fragments"]
    assert isinstance(extra_fragments, list)
    patch_dirs = payload["patch_dirs"]
    assert isinstance(patch_dirs, list)
    warnings = payload["warnings"]
    assert isinstance(warnings, list)
    expected = payload["expected_config"]
    assert isinstance(expected, list)
    lines = [
        f"target arch: {payload['target_arch']}",
        f"profiles:    {', '.join(str(p) for p in resolved)} (base {base})",
        # Only stated when it applies: a skipped gate is worth a line, an applied one is the norm.
        *(
            ["build gates: skipped (adopted kernel: a [foreign] scenario has no .config we built)"]
            if payload["build_gates"] == "skipped"
            else []
        ),
        "fragments (from profiles):",
        *[f"  {f}" for f in fragments],
        "extra fragments (from [build] extra_fragments):",
        *(([f"  {f}" for f in extra_fragments]) if extra_fragments else ["  (none)"]),
        "patches (from [build] patch_dirs):",
        *(([f"  {p}" for p in patch_dirs]) if patch_dirs else ["  (none)"]),
        "warnings:",
        *(([f"  {w}" for w in warnings]) if warnings else ["  (none)"]),
        "expected config (pending build):",
        *[f"  {e['symbol']}={e['value']} [{e['severity']}]" for e in expected],
    ]
    return "\n".join(lines)


def _session_run_id(requested: str) -> str:
    """Which run `--run`/`--insmod`/`--rmmod`/`--upload` should act on.

    `latest` used to mean the newest run in the whole workspace -- a single global symlink. With
    two sessions live that silently targets whichever guest booted last, so an exploit could be
    delivered to the wrong one. It now means "the run belonging to the tmux session I am typing
    in", which is also the more obviously-correct reading with a single session. An explicit
    --run-id always wins, and outside a LIKE-DBG session it falls back to the global pointer.
    """
    if requested != "latest":
        return requested
    active = Session("LIKE-DBG").get_option(_ACTIVE_RUN_DIR_OPTION)
    return Path(active).name if active else "latest"


def _claim_ports(rr: RunResolution) -> RunResolution:
    """Bind-check this boot's host ports and re-point the ones nobody chose.

    Runs before RunRecorder.start so run.json records the port `--run` will actually reach, and
    before the pipeline so QEMU, the published container port and gdb all agree.
    """
    plan = resolve_ports(rr.effective_debuggee, rr.provenance)
    for note in plan.notes:
        logger.info(f"port: {note}")
    return dataclasses.replace(rr, effective_debuggee=plan.debuggee) if plan.notes else rr


# A `[source] kind = "commit"` value is a full sha; truncated so one boot cannot fill the
# tmux status bar with a name nobody reads to the end anyway.
_NAME_PART_MAX = 12


def default_boot_label(version: str, profile_base: str) -> str:
    """Name a scenario-less boot after what actually varies between them: kernel and profile.

    `start_kgdb` with no -c is the commonest invocation, so it must not be the least informative
    name: two of them side by side are `6.6.30-exploit-dev` and `6.6.30-kasan`, not `default` and
    `default-2`.
    """
    v = version[:_NAME_PART_MAX]
    return f"{v}-{profile_base}" if profile_base else v


def use_boot_label(build_label: str) -> str:
    """`linux-6.6.30-a1b2c3d4` -> `6.6.30-a1b2c3d4`; every build carries the same prefix, so it
    distinguishes nothing and only costs status-bar room."""
    return build_label.removeprefix("linux-") or build_label


def _start_named_session(label: str) -> Session:
    """Take over the current tmux session under a name that says what it is debugging.

    Named per boot rather than a single global "LIKE-DBG" so a second scenario can be booted
    while the first is still live: `rename-session` to a name tmux already holds fails outright,
    which is how a leftover session used to block every later run.
    """
    session = Session("LIKE-DBG")
    name = unique_session_name(
        f"LIKE-DBG-{slug(label)}", session.list_sessions(), current=session.current_session_name()
    )
    session.start(name)
    session.name = name
    logger.info(f"tmux session: {name}")
    return session


# tmux layout: the host CLI (top-left) and the Debuggee/QEMU console (bottom-left) share the left
# column; the Debugger (pwndbg/GEF) takes the full-height right column, where it needs the vertical
# room for registers, disassembly, source, and backtrace. See run_in_new_pane's `full` (-f).
_DEBUGGER_WIDTH_PCT = 62  # Debugger share of the full window width (spans the full height, on the right)
_DEBUGGEE_HEIGHT_PCT = 50  # Debuggee (QEMU) share of the left column height, below the host CLI


def _make_pane_launchers(
    session: Session,
    host: HostProfile,
    *,
    workspace: Path,
    debugger_image: str,
    gdb_mount_source: str,
    recorder: RunRecorder | None,
    exploit_share: Path | None = None,
    debuginfod_urls: str | None = None,
    debuginfod_cache: Path | None = None,
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
        # Debuggee (QEMU) below the host CLI, in the left column.
        debuggee_pane = session.run_in_new_pane(target=base_pane, direction="v", percent=_DEBUGGEE_HEIGHT_PCT, cmd=cmd)
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
            debuginfod_urls=debuginfod_urls,
            debuginfod_cache=debuginfod_cache,
        )
        session.set_option("@likedbg_debugger_cmd", cmd)
        # Debugger on the full-height right column. -f (full=True) spans the whole window height even
        # though the left column is already split into the host CLI and the Debuggee above.
        debugger_pane = session.run_in_new_pane(
            target=base_pane,
            direction="h",
            percent=_DEBUGGER_WIDTH_PCT,
            full=True,
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
    sanitizer_breakpoints: tuple[str, ...] = (),
    exploit_share: Path | None = None,
    debuginfod_enabled: bool = False,
    debuginfod_urls: str = "",
    debuginfod_cache: Path | None = None,
    ccache: bool = False,
    ccache_max_size: str = "5G",
    max_size: str = "",
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
        debuginfod_urls=(debuginfod_urls if debuginfod_enabled else None),
        debuginfod_cache=(debuginfod_cache if debuginfod_enabled else None),
    )

    return Pipeline(
        [
            DownloadStage(_fetch, dl_dir=dl_dir),
            UnpackStage(
                container,
                recipe=build_recipe,
                kernel_volume=kernel_volume,
                workspace=workspace,
                patch_dirs=patch_dirs,
                chown_to=chown_to,
            ),
            BuildStage(
                container,
                recipe=build_recipe,
                kbuilder_image=KBUILDER_IMAGE,
                workspace=workspace,
                kernel_volume=kernel_volume,
                chown_to=chown_to,
                ccache=ccache,
                ccache_max_size=ccache_max_size,
            ),
            CacheEvictionStage(container, workspace=workspace, max_size=max_size, volume=kernel_volume),
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
                sanitizer_breakpoints=sanitizer_breakpoints,
                modules_gdb=(f"{EXPLOIT_MOUNT}/modules.gdb" if exploit_share is not None else None),
                debuginfod_enabled=debuginfod_enabled,
                debuginfod_urls=debuginfod_urls,
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
    sanitizer_breakpoints: tuple[str, ...] = (),
    exploit_share: Path | None = None,
    debuginfod_enabled: bool = False,
    debuginfod_urls: str = "",
    debuginfod_cache: Path | None = None,
) -> Pipeline:
    launch_debuggee, run_gdb = _make_pane_launchers(
        session,
        host,
        workspace=workspace,
        debugger_image=debugger_image,
        gdb_mount_source=gdb_mount_source,
        recorder=recorder,
        exploit_share=exploit_share,
        debuginfod_urls=(debuginfod_urls if debuginfod_enabled else None),
        debuginfod_cache=(debuginfod_cache if debuginfod_enabled else None),
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
                sanitizer_breakpoints=sanitizer_breakpoints,
                modules_gdb=(f"{EXPLOIT_MOUNT}/modules.gdb" if exploit_share is not None else None),
                debuginfod_enabled=debuginfod_enabled,
                debuginfod_urls=debuginfod_urls,
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
    sanitizer_breakpoints: tuple[str, ...] = (),
    debuginfod_enabled: bool = False,
    debuginfod_urls: str = "",
    debuginfod_cache: Path | None = None,
    exploit_flags: tuple[str, ...] = (),
    foreign_net: bool = True,
    foreign_net_iface: str = "eth0",
    force_rebuild: bool = False,
) -> Pipeline:
    # ADR-0010: a foreign guest has no exploit share (no guest-side delivery path): never mount one,
    # and DebuggerStage below is left at its modules_gdb=None default (no modules.gdb to watch).
    launch_debuggee, run_gdb = _make_pane_launchers(
        session,
        host,
        workspace=workspace,
        debugger_image=debugger_image,
        gdb_mount_source=gdb_mount_source,
        recorder=recorder,
        exploit_share=None,
        debuginfod_urls=(debuginfod_urls if debuginfod_enabled else None),
        debuginfod_cache=(debuginfod_cache if debuginfod_enabled else None),
    )

    return Pipeline(
        [
            ForeignAdoptStage(
                foreign=foreign,
                qemu_extra=qemu_extra,
                foreign_net=foreign_net,
                foreign_net_iface=foreign_net_iface,
            ),
            ForeignRepackStage(
                container,
                foreign=foreign,
                exploit=exploit,
                image=musl_image,
                out_dir=out_dir,
                workspace=workspace,
                exploit_flags=exploit_flags,
                force=force_rebuild,
            ),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image, workspace=workspace),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
                sanitizer_breakpoints=sanitizer_breakpoints,
                debuginfod_enabled=debuginfod_enabled,
                debuginfod_urls=debuginfod_urls,
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
    cache.touch_last_used(workspace, label)
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
    rr = _claim_ports(rr)
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
    debuginfod_enabled = resolve_debuginfod_enabled(use_settings.debugger.debuginfod, is_foreign=False)
    debuginfod_cache = workspace / "artifacts" / "cache" / "debuginfod"
    if debuginfod_enabled:
        debuginfod_cache.mkdir(
            parents=True, exist_ok=True
        )  # pre-create the leaf so docker bind-mounts a host-owned dir, not a root-owned new one
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
        sanitizer_breakpoints=use_settings.debugger.sanitizer_breakpoints,
        exploit_share=exploit_share,
        debuginfod_enabled=debuginfod_enabled,
        debuginfod_urls=use_settings.debugger.debuginfod_urls,
        debuginfod_cache=debuginfod_cache,
    )
    _save_rerun_request(
        session,
        workspace=workspace,
        kind="use",
        scenario=custom_ini.resolve() if custom_ini is not None else None,
        profile_arg=profile_arg,
        run_dir=recorder.run_dir,
        use_label=label,
        rootfs_label=rootfs_label or "",
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
    force_rebuild: bool = False,
) -> int:
    cfg0 = load_config(workspace, scenario=scenario)
    fcfg = cfg0.settings.foreign
    if not fcfg.image:
        raise ForeignError("no [foreign].image configured", remedy="set [foreign].image in your scenario")

    name = scenario.stem if scenario is not None else "foreign"
    out_dir = workspace / "artifacts" / "foreign" / name
    # musl (+ base) must exist before we can extract vmlinux / repack.
    stale = _ensure_images(container, workspace, specs=images.foreign_prep_images())
    # A stale like_musl is the one way a Stamp can lie (ADR-0018). `ensure_current` only WARNS, so
    # this boot's repack runs in the OLD image while its Stamp records the NEW musl_image_sha -- a
    # hash of the image's build files, not of the built image. The user then runs `--build-images`
    # as told, the sha does not move, and every later boot reuses an initramfs holding a binary the
    # current toolchain never produced. Distrust both foreign Stamps until the image is refreshed.
    force = force_rebuild or MUSL_IMAGE in stale
    if MUSL_IMAGE in stale:
        logger.info(
            f"foreign exploit: rebuilding derived artifacts ({MUSL_IMAGE} is stale, so no build record is trusted)"
        )
    fk = resolve_foreign(container, fcfg, workspace, out_dir=out_dir, image=MUSL_IMAGE, force=force)

    # Inject the detected arch so HostProfile.detect / QEMU / gdb follow the foreign kernel.
    cfg, host, rr = resolve_for_run(
        workspace,
        profile_arg=profile_arg,
        scenario=scenario,
        cli_overrides={"general": {"arch": fk.arch}},
        # Profile expectations describe LIKE-DBG-built kernels. A foreign bzImage may support a
        # runtime flag even when the selected local profile would build its Kconfig dependency off.
        validate_build_gates=False,
    )
    # ADR-0010/0017: a foreign guest has no SSH/9p *control* transport. Forcing guest_net=False
    # (and share=False) drops the SSH hostfwd + the run.json `guest` block, so --run/--insmod/--rmmod
    # refuse cleanly instead of trying to SSH to a nonexistent sshd. The outbound NIC that unblocks
    # the challenge initramfs's ifup wait is a separate axis ([foreign] net -> foreign_net, never
    # guest_net), so it is unaffected by this override. Both RunRecorder.start (run.json `guest`
    # block) and the pipeline's DebuggeeStage (QEMU argv) read effective_debuggee off the
    # RunResolution, so overriding it here fixes both at once.
    eff = rr.effective_debuggee.model_copy(update={"guest_net": False, "share": False})
    rr = dataclasses.replace(rr, effective_debuggee=eff)
    # A foreign command line remains verbatim unless the user/scenario explicitly selected a
    # runtime mitigation. Defaults and profile defaults must not rewrite a challenge's run.sh.
    foreign_mitigation_overrides = tuple(
        key
        for key in (
            "kaslr",
            "kpti",
            "fgkaslr",
            "mitigations",
            "slab_merge",
            "init_on_alloc",
            "init_on_free",
            "randomize_kstack_offset",
            "hardened_usercopy",
        )
        if rr.provenance.get(("debuggee", key)) in {LAYER_LOCAL, LAYER_SCENARIO, LAYER_CLI}
    )
    _ensure_images(container, workspace, specs=images.required_for_foreign(host))

    exploit = resolve_input_path(workspace, fcfg.exploit) if fcfg.exploit else None
    if exploit is not None and not exploit.is_file():
        raise ForeignError(f"[foreign].exploit not found: {exploit}", remedy="check the path")

    rr = _claim_ports(rr)
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
        foreign_mitigation_overrides=foreign_mitigation_overrides,
        recorder=recorder,
    )
    debuginfod_enabled = resolve_debuginfod_enabled(cfg.settings.debugger.debuginfod, is_foreign=True)
    debuginfod_cache = workspace / "artifacts" / "cache" / "debuginfod"
    if debuginfod_enabled:
        debuginfod_cache.mkdir(
            parents=True, exist_ok=True
        )  # pre-create the leaf so docker bind-mounts a host-owned dir, not a root-owned new one
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
        sanitizer_breakpoints=cfg.settings.debugger.sanitizer_breakpoints,
        debuginfod_enabled=debuginfod_enabled,
        debuginfod_urls=cfg.settings.debugger.debuginfod_urls,
        debuginfod_cache=debuginfod_cache,
        exploit_flags=cfg.settings.exploit.flags,
        foreign_net=fcfg.net,
        foreign_net_iface=fcfg.net_iface,
        force_rebuild=force,
    )
    _save_rerun_request(
        session,
        workspace=workspace,
        kind="foreign",
        scenario=scenario,
        profile_arg=profile_arg,
        run_dir=recorder.run_dir,
    )
    pipeline.run(ctx)
    return 0


def _ensure_images(container: ContainerService, workspace: Path, *, specs: tuple[images.ImageSpec, ...]) -> list[str]:
    """Build missing images, warn about stale ones (ADR-0004 keeps that warn-only), and return the
    stale tags so a caller whose derived artifacts are keyed by an image's BUILD INPUTS -- not by the
    built image -- can distrust them (see cmd_foreign)."""
    try:
        stale = images.ensure_current(container, workspace, specs)
    except OSError as exc:
        # The specs' build inputs are the repo's own dockerfiles. Missing them means the workspace
        # is not a LIKE-DBG checkout -- almost always `start_kgdb` run from the wrong directory,
        # since the workspace is just the cwd. Say that, rather than a traceback about a dockerfile.
        raise ConfigError(
            f"{workspace} does not look like a LIKE-DBG workspace ({exc.filename} is missing)",
            remedy="cd to your like-dbg checkout and run it from there",
        ) from exc
    for tag in stale:
        logger.warning(f"image {tag} looks stale (build inputs changed); run `start_kgdb --build-images` to refresh")
    return stale


def _volume_du(container: ContainerService, path: str, *, volume: str = KERNEL_VOLUME) -> str | None:
    """Best-effort `du -sb <path>` inside a throwaway container mounting `volume` ro at VOLUME_MOUNT.
    Returns None (never raises) if Docker/du is unavailable, so `--list` stays best-effort."""
    try:
        c = container.run_detached(
            BASE_IMAGE,
            volumes={volume: {"bind": VOLUME_MOUNT, "mode": "ro"}},
            detach=True,
            tty=True,
        )
        try:
            out = container.exec(c, f"du -sb {shlex.quote(path)}").output.strip()
        finally:
            container.stop(c)
        size = int(out.split()[0])
    except Exception:  # noqa: BLE001 - `--list` should remain best-effort if Docker/du is unavailable.
        return None
    return str(size)


def _volume_build_size(container: ContainerService, manifest: Manifest, *, volume: str = KERNEL_VOLUME) -> str | None:
    kernel_root = manifest.paths.get("kernel_root")
    if manifest.storage_mode != "volume" or not kernel_root:
        return None
    return _volume_du(container, kernel_root, volume=volume)


def _dir_size(path: Path) -> int | None:
    """Best-effort recursive size of a host directory tree; None if it doesn't exist or errors out."""
    if not path.is_dir():
        return None
    total = 0
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
    except OSError:
        return None
    return total


def _source_size(workspace: Path, manifest: Manifest, *, container: ContainerService | None = None) -> str:
    """Best-effort size of a shared source tree: du inside the volume (mirrors the builds
    section), falling back to a recursive host dir size for bind mode. Source manifests don't
    carry `storage_mode`/`paths` (they're shared across builds), so the path is derived from
    the label the same way remove_source/UnpackStage do."""
    if container is not None:
        volume_size = _volume_du(container, f"{VOLUME_MOUNT}/src/{manifest.label}")
        if volume_size is not None:
            return volume_size
    total = _dir_size(workspace / "artifacts" / cache.TREE_ROOT / "src" / manifest.label)
    return str(total) if total is not None else "-"


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


def _build_size(workspace: Path, manifest: Manifest, *, container: ContainerService | None = None) -> str:
    """Get build size: prefer stamped size_bytes if > 0, else fall back to best-effort helpers."""
    if manifest.size_bytes > 0:
        return str(manifest.size_bytes)
    return _artifact_size(workspace, manifest, container=container)


def _source_size_stamped(workspace: Path, manifest: Manifest, *, container: ContainerService | None = None) -> str:
    """Get source size: prefer stamped size_bytes if > 0, else fall back to best-effort helpers."""
    if manifest.size_bytes > 0:
        return str(manifest.size_bytes)
    return _source_size(workspace, manifest, container=container)


def summarize_cache(workspace: Path, *, container: ContainerService | None = None) -> list[str]:
    builds = cache.list_manifests(workspace, "build")
    rootfs = cache.list_manifests(workspace, "rootfs")
    sources = cache.list_manifests(workspace, "source")
    if not builds and not rootfs and not sources:
        return ["(cache empty)"]
    lines: list[str] = []
    if builds or rootfs:
        lines.append("kind    label  version  arch  size  created  last_used")
        for m in [*builds, *rootfs]:
            mp = cache.manifest_path(workspace, m.kind, m.label)
            created = datetime.fromtimestamp(mp.stat().st_mtime, tz=UTC).date().isoformat()
            size = _build_size(workspace, m, container=container)
            # Only show last_used for builds (rootfs doesn't have it)
            last_used_val = m.last_used if m.kind == "build" else "-"
            lines.append(f"{m.kind}  {m.label}  {m.version or '-'}  {m.arch}  {size}  {created}  {last_used_val}")
    if sources:
        lines.append("shared sources:")
        for s in sources:
            refcount = cache.source_refcount(workspace, s.key)
            size = _source_size_stamped(workspace, s, container=container)
            lines.append(f"{s.label}  {s.version or '-'}  refcount={refcount}  size={size}")
    return lines


def cmd_list(workspace: Path, *, container: ContainerService | None = None) -> int:
    for line in summarize_cache(workspace, container=container):
        logger.info(line)
    return 0


def _remove_orphaned_source(container: ContainerService, workspace: Path, build: Manifest) -> None:
    """After removing a build manifest, drop its source tree too if no other build still
    references it (refcount 0). Thin wrapper: `cache.drop_orphaned_source` is the single
    canonical implementation, shared with `cache.prune_cache`."""
    label = cache.drop_orphaned_source(container, workspace, build, volume=KERNEL_VOLUME)
    if label:
        logger.info(f"removed source {label}")


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
        if m.kind == "build":
            _remove_orphaned_source(container, workspace, m)
    if clean_all:
        # Safety net: every build's source should already be gone via the refcount check above,
        # but sweep the sources/ registry explicitly so no leftover (e.g. orphaned pre-existing)
        # source survives a --clean-all. storage_mode isn't recorded on source manifests (shared
        # across builds), so infer it from whether the bind-mode host tree actually exists.
        for s in cache.list_manifests(workspace, "source"):
            bind_tree = workspace / "artifacts" / cache.TREE_ROOT / "src" / s.label
            src_storage_mode = "bind" if bind_tree.is_dir() else "volume"
            cache.remove_source(container, workspace, s.label, storage_mode=src_storage_mode, volume=KERNEL_VOLUME)
            logger.info(f"removed source {s.label}")
        container.remove_volume(LIKEDBG_ZIG_CACHE_VOLUME)
        logger.info("removed exploit-compile cache volume")
    return 0


def _latest_run_build_label(workspace: Path) -> str | None:
    """Best-effort read of the latest run's build label (artifacts/runs/latest/run.json).
    Returns None if there is no recorded run, or it can't be read (never raises: --prune must
    stay usable even with a stale/missing `latest` pointer)."""
    run_json = workspace / "artifacts" / "runs" / "latest" / "run.json"
    if not run_json.is_file():
        return None
    try:
        data = json.loads(run_json.read_text())
    except (OSError, ValueError):
        return None
    label = data.get("build_label")
    return label if isinstance(label, str) and label else None


def cmd_prune(container: ContainerService, workspace: Path, *, size_arg: str | None, max_size: str) -> int:
    """Evict cached builds down to a target size: `--prune 30G` (explicit) or `--prune` alone
    (falls back to [cache] max_size). Protects the latest run's build (if any) from eviction."""
    target = cache.parse_size(size_arg) if size_arg else cache.parse_size(max_size)
    if target == 0 and not size_arg and not max_size:
        raise CacheError("--prune needs a size", remedy="pass --prune 30G or set [cache] max_size")
    label = _latest_run_build_label(workspace)
    protect = {label} if label else set()
    evicted = cache.prune_cache(container, workspace, target, protect=protect)
    if evicted:
        logger.info(f"pruned: {', '.join(evicted)}")
    else:
        logger.info("nothing to prune")
    return 0


def _missing_restart_state(name: str) -> SessionError:
    return SessionError(
        f"missing {name}; cannot restart Debuggee",
        remedy="start a fresh Debugging session with `uv run ./start_kgdb`",
    )


def _save_rerun_request(
    session: Session,
    *,
    workspace: Path,
    kind: str,
    scenario: Path | None,
    profile_arg: str,
    run_dir: Path,
    use_label: str = "",
    rootfs_label: str = "",
) -> None:
    request = {
        "version": 1,
        "workspace": str(workspace.resolve()),
        "kind": kind,
        "scenario": str(scenario.resolve()) if scenario is not None else "",
        "profile_arg": profile_arg,
        "use_label": use_label,
        "rootfs_label": rootfs_label,
    }
    session.set_option(_RERUN_OPTION, json.dumps(request, sort_keys=True))
    session.set_option(_ACTIVE_RUN_DIR_OPTION, str(run_dir))


def _load_rerun_request(session: Session, *, workspace: Path) -> RerunRequest:
    raw = session.get_option(_RERUN_OPTION)
    if not raw:
        raise SessionError("no active run to re-run", remedy="start a Debugging session with `uv run ./start_kgdb`")
    try:
        data = json.loads(raw)
        scenario_raw = data["scenario"]
        saved_workspace = Path(data["workspace"])
        kind = data["kind"]
        profile_arg = data["profile_arg"]
        use_label = data.get("use_label", "")
        rootfs_label = data.get("rootfs_label", "")
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionError("invalid active re-run state", remedy="start the session again") from exc
    scenario = Path(scenario_raw) if scenario_raw else None
    if (
        data.get("version") != 1
        or kind not in {"foreign", "normal", "use"}
        or scenario is not None
        and not scenario.is_absolute()
        or not isinstance(profile_arg, str)
        or not isinstance(use_label, str)
        or not isinstance(rootfs_label, str)
    ):
        raise SessionError("invalid active re-run state", remedy="start the session again")
    if saved_workspace != workspace.resolve():
        raise SessionError(
            "active run belongs to a different workspace",
            remedy=f"cd to {saved_workspace} or start a new session here",
        )
    if scenario is not None and not scenario.is_file():
        raise SessionError(f"stored scenario is missing: {scenario}", remedy="start a new session")
    return RerunRequest(
        kind=kind,
        scenario=scenario,
        profile_arg=profile_arg,
        use_label=use_label,
        rootfs_label=rootfs_label,
    )


def _stop_rerun_panes(session: Session) -> None:
    base_pane = session.get_option("@likedbg_base_pane_id")
    if not base_pane:
        raise SessionError("missing @likedbg_base_pane_id", remedy="start a fresh Debugging session")
    panes = (session.get_option("@likedbg_debugger_pane"), session.get_option("@likedbg_debuggee_pane"))
    if any(pane == base_pane for pane in panes if pane):
        raise SessionError(
            "refusing to close the host pane from corrupted re-run state", remedy="start a fresh Debugging session"
        )
    for pane in panes:  # debugger first, then QEMU
        if pane and session.pane_exists(pane):
            session.kill_pane(pane)
    session.unset_option("@likedbg_debugger_pane")
    session.unset_option("@likedbg_debuggee_pane")


def _rerun_argv(request: RerunRequest, *, force_rebuild: bool = False) -> list[str]:
    args: list[str] = []
    if request.scenario is not None:
        args += ["--config", str(request.scenario)]
    if request.profile_arg:
        args += ["--profile", request.profile_arg]
    if request.kind == "use":
        args += ["--use", request.use_label]
        if request.rootfs_label:
            args += ["--rootfs", request.rootfs_label]
    elif force_rebuild:
        args.append("--force-rebuild")
    return args


def cmd_rerun(session: Session, workspace: Path, *, force_rebuild: bool = False) -> int:
    request = _load_rerun_request(session, workspace=workspace)
    # Preflight before touching live panes: a broken/deleted scenario must not destroy the current session.
    cfg = load_config(workspace, scenario=request.scenario)
    if request.kind == "foreign" and not cfg.settings.foreign.image:
        raise SessionError("stored scenario is no longer a foreign run", remedy="start the desired scenario explicitly")
    if request.kind == "use" and not request.use_label:
        raise SessionError("stored --use run has no build label", remedy="start the desired cached build explicitly")
    # Docker connection is also established before teardown, so a stopped daemon leaves the live session intact.
    docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
    prior_run = session.get_option(_ACTIVE_RUN_DIR_OPTION)
    _stop_rerun_panes(session)
    if prior_run:
        try:
            RunRecorder.mark_restarted(Path(prior_run))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"could not mark prior run as restarted: {exc}")
    logger.info(f"restarting {request.kind} session")
    # Re-enter the normal CLI dispatch with reconstructed declarative selectors. This is not a raw
    # saved shell command: current TOML/files are re-read and each established launcher stays authoritative.
    return main(_rerun_argv(request, force_rebuild=force_rebuild))


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
            # Recreate below the host CLI (left column), matching launch_debuggee: the Debugger, if
            # still alive, keeps the full-height right column untouched.
            debuggee_pane = session.run_in_new_pane(
                target=base_pane, direction="v", percent=_DEBUGGEE_HEIGHT_PCT, cmd=cmd
            )
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

    Docker/tmux-free: safe to dispatch before any container/session setup.
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
    print(f"crash: {prim.kind}: {prim.title}")
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
    rootfs_label = read_run_state(run_dir, "run.json", error=ModuleError).get("rootfs_label", "")
    key = cache.load_manifest(workspace, "rootfs", rootfs_label).paths.get("ssh_key", "")
    if not key:
        raise ModuleError("rootfs has no recorded SSH key", remedy="rebuild the rootfs")
    return guest.GuestEndpoint(host=str(g["ssh_host"]), port=int(g["ssh_port"]), key=Path(key))


def _read_sections(
    ep: guest.GuestEndpoint,
    name: str,
    *,
    attempts: int = 3,
    sleep: Callable[[float], None] | None = None,
) -> list[tuple[str, str]]:
    """Read /sys/module/<name>/sections; retry the sysfs-population race after an insmod/reload
    until `.text` is present and non-zero, up to `attempts`. Modifies no guest state."""
    # Resolve time.sleep at call time (not as a default arg) so tests can monkeypatch cli.time.sleep.
    _sleep = sleep if sleep is not None else time.sleep
    secs: list[tuple[str, str]] = []
    for i in range(attempts):
        secs_raw = guest.run(
            ep, f"for s in /sys/module/{name}/sections/.*; do echo $(basename $s) $(cat $s); done"
        ).stdout
        secs = []
        for ln in secs_raw.replace("\r\n", "\n").split("\n"):
            f = ln.split()
            if len(f) == 2 and f[0].startswith("."):
                secs.append((f[0], f[1]))
        text = dict(secs).get(".text")
        if text and int(text, 16):
            return secs
        if i + 1 < attempts:
            _sleep(0.5)
    return secs


def cmd_insmod(workspace: Path, *, run_id: str, path: str, args: str, force_unload: bool) -> int:
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    run_json = read_run_state(run_dir, "run.json", error=ModuleError)
    g = guest_endpoint(
        run_json,
        error=ModuleError,
        foreign_remedy=(
            "custom modules need the SSH transport; a foreign guest loads its own modules from "
            "its initramfs and is driven from the serial console"
        ),
    )
    ep = _guest_endpoint(workspace, run_dir, g)
    share_dir = (workspace / g["share_dir"]).resolve()
    out_dir = share_dir / "modules"

    # build context (kernel tree + toolchain env): reads the run's build label + host profile + config.
    build_label = run_json.get("build_label", "")
    host_json = read_run_state(run_dir, "host.json", error=ModuleError)
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
            kernel_root=loc.objdir,
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
        # read runtime section addresses from the guest and log a lifecycle `load` event.
        secs = _read_sections(ep, name)
        text = dict(secs).get(".text")
        modules_gdb = share_dir / "modules.gdb"
        if text and int(text, 16):
            others = " ".join(f"{s} {a}" for s, a in secs if s != ".text")
            modules_gdb.parent.mkdir(parents=True, exist_ok=True)
            with modules_gdb.open("a") as fh:
                fh.write(f"load {name} {EXPLOIT_MOUNT}/modules/{ko.name} {text} {others}\n".rstrip() + "\n")
            note = f"symbols will load at your next gdb stop (or `source {EXPLOIT_MOUNT}/modules.gdb`)"
        else:
            note = f"no .text section read; add-symbol-file {g['share_mount']}/modules/{ko.name} manually"
        print(f"[likedbg] loaded {name} (rc={res.rc}): {g['share_mount']}/modules/{ko.name}; {note}")
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
    """Live exploit delivery over the serial console (see foreign.console_upload). Optional
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
        host_json = read_run_state(run_dir, "host.json", error=ForeignError)
        container = ContainerService(docker_env.make_client(host=docker_env.resolve_docker_host(env=os.environ)))
        _ensure_images(container, workspace, specs=images.foreign_prep_images())
        f = compile_exploit(
            container,
            src=f,
            arch=host_json["target_arch"],
            out=run_dir / "exploit" / f.stem,
            image=MUSL_IMAGE,
            extra_flags=exploit_flags_for(workspace),
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
    g = guest_endpoint(
        read_run_state(run_dir, "run.json", error=ModuleError),
        error=ModuleError,
        foreign_remedy=(
            "custom modules need the SSH transport; a foreign guest loads its own modules from "
            "its initramfs and is driven from the serial console"
        ),
    )
    ep = _guest_endpoint(workspace, run_dir, g)
    if not guest.wait_ready(ep):
        raise ModuleError(f"guest not reachable at {ep.host}:{ep.port}", remedy="boot + continue the session")
    res = modules.unload(ep, name, force=force_unload)
    if res.rc == 0:
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
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--clean", default="")
    parser.add_argument("--clean-all", action="store_true")
    parser.add_argument("--prune", nargs="?", const="", default=None, metavar="SIZE")
    parser.add_argument("--use", default="")
    parser.add_argument("--rootfs", default="")
    parser.add_argument("--build-images", action="store_true")
    parser.add_argument("--restart-debuggee", action="store_true")
    parser.add_argument("--re-run", action="store_true")
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
            return cmd_run(workspace, run_id=_session_run_id(args.run_id), exploit=args.run, args=args.args)
        if args.upload:
            return cmd_upload(workspace, run_id=_session_run_id(args.run_id), file=args.upload)
        if args.insmod:
            return cmd_insmod(
                workspace,
                run_id=_session_run_id(args.run_id),
                path=args.insmod,
                args=args.args,
                force_unload=args.force_unload,
            )
        if args.rmmod:
            return cmd_rmmod(
                workspace, run_id=_session_run_id(args.run_id), name=args.rmmod, force_unload=args.force_unload
            )
        if args.re_run:
            if args.config or args.profile or args.use or args.rootfs:
                parser.error("--re-run cannot be combined with launch selectors")
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            try:
                return cmd_rerun(session, workspace, force_rebuild=args.force_rebuild)
            except LikeDbgError as exc:
                logger.error(str(exc))
                try:
                    session.display_message(f"LIKE-DBG re-run failed: {exc.message}")
                except LikeDbgError:
                    pass
                return 1
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
        # Early paths that don't need the full TOML flow: --build-images, --clean*
        cfg = load_config(workspace, scenario=_scenario_path(workspace, args.config))
        client = docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
        container = ContainerService(client)
        if args.build_images:
            images.build_images(container, workspace)
            return 0
        if args.clean or args.clean_all:
            return cmd_clean(container, workspace, label=args.clean or None, clean_all=args.clean_all)
        if args.prune is not None:
            return cmd_prune(container, workspace, size_arg=args.prune, max_size=cfg.settings.cache.max_size)
        if cfg.settings.foreign.image:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            fscen = _scenario_path(workspace, args.config)
            session = _start_named_session(fscen.stem if fscen is not None else "foreign")
            return cmd_foreign(
                container,
                session,
                workspace,
                scenario=_scenario_path(workspace, args.config),
                profile_arg=args.profile,
                force_rebuild=args.force_rebuild,
            )
        if args.use:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            # A --use boot is identified by the cached build it reuses, not by a scenario file.
            session = _start_named_session(use_boot_label(args.use))
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
        if not os.getenv("TMUX"):
            logger.error("Not running inside a TMUX session. Start tmux first.")
            return 2
        run_res = _claim_ports(run_res)
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
        session = _start_named_session(
            scenario.stem if scenario is not None else default_boot_label(version, run_res.profiles.base or "")
        )
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
        debuginfod_enabled = resolve_debuginfod_enabled(cfg.settings.debugger.debuginfod, is_foreign=False)
        debuginfod_cache = workspace / "artifacts" / "cache" / "debuginfod"
        if debuginfod_enabled:
            debuginfod_cache.mkdir(
                parents=True, exist_ok=True
            )  # pre-create the leaf so docker bind-mounts a host-owned dir, not a root-owned new one
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
            sanitizer_breakpoints=cfg.settings.debugger.sanitizer_breakpoints,
            exploit_share=exploit_share,
            debuginfod_enabled=debuginfod_enabled,
            debuginfod_urls=cfg.settings.debugger.debuginfod_urls,
            debuginfod_cache=debuginfod_cache,
            ccache=cfg.settings.build.ccache,
            ccache_max_size=cfg.settings.build.ccache_max_size,
            max_size=cfg.settings.cache.max_size,
        )
        _save_rerun_request(
            session,
            workspace=workspace,
            kind="normal",
            scenario=scenario.resolve() if scenario is not None else None,
            profile_arg=args.profile,
            run_dir=recorder.run_dir,
        )
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
