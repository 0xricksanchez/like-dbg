"""RunRecorder: the runtime seam. Owns artifacts/runs/<run-id>/ — its layout, run.json status
machine, and the resolved-profile/fragment snapshots. Callers get paths, not directory knowledge."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import asdict
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Literal

from likedbg.config import Settings
from likedbg.debug_profiles import ProfileVerification
from likedbg.debug_profiles import ResolvedDebugProfiles
from likedbg.debug_profiles import RunResolution
from likedbg.host_profile import HostProfile
from likedbg.input_hash import hash_file

RunStatus = Literal["created", "profile-verification-failed", "launching", "launched", "launch-failed"]
SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id(build_label: str) -> str:
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{build_label}"


def _point(link: Path, target: Path) -> None:
    """Point `link` at `target` — try symlink, fall back to .txt if OS refuses."""
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target.name if link.parent == target.parent else target)
    except OSError:
        try:
            link.write_text(str(target))
        except OSError:
            pass


def _provenance_json(prov: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for (section, key), layer in prov.items():
        out.setdefault(section, {})[key] = layer
    return out


def _write_profiles_json(
    run_dir: Path, workspace: Path, rr: RunResolution, profiles: ResolvedDebugProfiles
) -> None:
    def _snapshot(rel: str, subdir: str) -> dict[str, str]:
        src = workspace / rel
        dest = run_dir / subdir / rel
        sha = ""
        if src.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            sha = hash_file(src)
        return {"source": rel, "snapshot": f"{subdir}/{rel}", "sha256": sha}

    profile_files = [_snapshot(f"configs/profiles/{n}.toml", "profiles") for n in profiles.names]
    fragments = [_snapshot(rel, "fragments") for rel in rr.fragments]
    payload: dict[str, Any] = {
        "requested": list(rr.profiles.names),
        "base": profiles.base,
        "resolved": list(profiles.names),
        "implied_by": {k: list(v) for k, v in rr.implied_by.items()},
        "profile_files": profile_files,
        "fragments": fragments,
        "warnings": list(rr.profile_warnings),
        "runtime_notes": list(rr.runtime_notes) + list(rr.runtime_overrides),
    }
    (run_dir / "profiles.json").write_text(json.dumps(payload, indent=2, sort_keys=True))


class RunRecorder:
    def __init__(self, run_dir: Path, run_json: dict[str, Any]) -> None:
        self._dir = run_dir
        self._run = run_json

    @property
    def run_dir(self) -> Path:
        return self._dir

    @property
    def likedbg_log(self) -> Path:
        return self._dir / "logs" / "likedbg.log"

    @property
    def debuggee_pane_log(self) -> Path:
        return self._dir / "logs" / "debuggee-pane.log"

    @property
    def debugger_pane_log(self) -> Path:
        return self._dir / "logs" / "debugger-pane.log"

    @classmethod
    def start(
        cls,
        *,
        workspace: Path,
        requested_settings: Settings,
        run_resolution: RunResolution,
        host: HostProfile,
        build_label: str,
        rootfs_label: str,
        profiles: ResolvedDebugProfiles,
    ) -> RunRecorder:
        run_id = _run_id(build_label)
        run_dir = workspace / "artifacts" / "runs" / run_id
        for sub in ("logs", "commands", "kernel", "profiles", "fragments"):
            (run_dir / sub).mkdir(parents=True, exist_ok=True)

        # requested + effective settings
        (run_dir / "settings.requested.json").write_text(requested_settings.model_dump_json(indent=2))
        effective: dict[str, Any] = requested_settings.model_dump()
        effective["debuggee"] = run_resolution.effective_debuggee.model_dump()
        effective["_provenance"] = _provenance_json(run_resolution.provenance)
        (run_dir / "settings.effective.json").write_text(json.dumps(effective, indent=2, sort_keys=True))

        # host profile — dataclass, use asdict
        (run_dir / "host.json").write_text(json.dumps(asdict(host), indent=2, sort_keys=True))

        _write_profiles_json(run_dir, workspace, run_resolution, profiles)

        now = _utc_now()
        run_json: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "kind": "debugging-session",
            "status": "created",
            "created_at": now,
            "build_label": build_label,
            "rootfs_label": rootfs_label,
            "host": "host.json",
            "settings_requested": "settings.requested.json",
            "settings_effective": "settings.effective.json",
            "profiles": "profiles.json",
            "commands": {"qemu": "commands/qemu.sh", "gdb": "commands/gdb.sh"},
            "logs": {
                "likedbg": "logs/likedbg.log",
                "debuggee": "logs/debuggee-pane.log",
                "debugger": "logs/debugger-pane.log",
            },
            "warnings": list(run_resolution.profile_warnings),
            "status_history": [{"status": "created", "at": now}],
        }
        rec = cls(run_dir, run_json)
        rec._flush()
        _point(workspace / "artifacts" / "runs" / "latest", run_dir)
        return rec

    def _flush(self) -> None:
        path = self._dir / "run.json"
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".json.tmp")
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(self._run, indent=2, sort_keys=True))
        Path(tmp).replace(path)

    def set_status(self, status: RunStatus, *, message: str | None = None) -> None:
        self._run["status"] = status
        entry: dict[str, str] = {"status": status, "at": _utc_now()}
        if message:
            entry["message"] = message
        self._run["status_history"].append(entry)
        self._flush()

    def add_warning(self, code: str, message: str) -> None:
        self._run["warnings"].append({"at": _utc_now(), "code": code, "message": message})
        self._flush()

    def record_command(self, kind: Literal["qemu", "gdb"], *, shell: str, argv: list[str]) -> None:
        (self._dir / "commands" / f"{kind}.sh").write_text(shell + "\n")
        (self._dir / "commands" / f"{kind}.argv.json").write_text(json.dumps(argv, indent=2))

    def record_profile_verification(self, verification: ProfileVerification) -> None:
        payload: dict[str, Any] = {
            "satisfied": [e.symbol for e in verification.satisfied],
            "missing_hard": [e.symbol for e in verification.missing_hard],
            "missing_soft": [e.symbol for e in verification.missing_soft],
            "warnings": list(verification.warnings),
        }
        (self._dir / "profiles" / "verification.json").write_text(json.dumps(payload, indent=2))

    def record_kernel_paths(
        self,
        *,
        config: Path | str | None,
        system_map: Path | str,
        vmlinux: Path | str,
        image: Path | str,
    ) -> None:
        kdir = self._dir / "kernel"
        if config is not None and Path(str(config)).is_file():
            shutil.copyfile(str(config), kdir / "config")
        (kdir / "System.map.pointer").write_text(str(system_map))
        (kdir / "vmlinux.pointer").write_text(str(vmlinux))
        (kdir / "image.pointer").write_text(str(image))
