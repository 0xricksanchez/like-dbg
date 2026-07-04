import json
from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.config import Settings
from likedbg.debug_profiles import ResolvedDebugProfiles
from likedbg.debug_profiles import RunResolution
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes
from likedbg.run_artifacts import RunRecorder


def _rr(*, effective_debuggee: DebuggeeCfg | None = None) -> RunResolution:
    return RunResolution(
        requested_settings=Settings(),
        provenance={("debuggee", "kaslr"): "default"},
        target_arch="arm64",
        profiles=ResolvedDebugProfiles(
            names=("exploit-dev",), base="exploit-dev", expected_config=(), future_breakpoint_groups=()
        ),
        fragments=(),
        effective_debuggee=effective_debuggee if effective_debuggee is not None else Settings().debuggee,
        runtime_defaults={},
        runtime_overrides=(),
        extra_boot_args=(),
        profile_warnings=(),
        runtime_notes=(),
        implied_by={},
    )


def _host(tmp_path: Path) -> HostProfile:
    p = Probes(
        system=lambda: "darwin",
        machine=lambda: "arm64",
        kvm_accessible=lambda: False,
        hvf_supported=lambda: True,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: False,
    )
    return HostProfile.detect(Settings(), tmp_path, p)


def _start_recorder(tmp_path: Path, *, effective_debuggee: DebuggeeCfg | None = None) -> RunRecorder:
    return RunRecorder.start(
        workspace=tmp_path,
        requested_settings=Settings(),
        run_resolution=_rr(effective_debuggee=effective_debuggee),
        host=_host(tmp_path),
        build_label="linux-6.6.30-abcd1234",
        rootfs_label="rootfs-arm64-bookworm-deadbeef",
        profiles=_rr().profiles,
    )


def test_start_creates_layout_and_latest(tmp_path: Path) -> None:
    rec = RunRecorder.start(
        workspace=tmp_path,
        requested_settings=Settings(),
        run_resolution=_rr(),
        host=_host(tmp_path),
        build_label="linux-6.6.30-abcd1234",
        rootfs_label="rootfs-arm64-bookworm-deadbeef",
        profiles=_rr().profiles,
    )
    assert rec.run_dir.is_dir()
    run = json.loads((rec.run_dir / "run.json").read_text())
    assert run["status"] == "created" and run["schema_version"] == 1
    assert [h["status"] for h in run["status_history"]] == ["created"]
    assert (rec.run_dir / "settings.requested.json").is_file()
    assert (rec.run_dir / "profiles.json").is_file()
    effective = json.loads((rec.run_dir / "settings.effective.json").read_text())
    assert "debuggee" in effective
    assert isinstance(effective["_provenance"], dict)
    assert effective["_provenance"] == {"debuggee": {"kaslr": "default"}}
    host = json.loads((rec.run_dir / "host.json").read_text())
    assert "target_arch" in host
    latest = tmp_path / "artifacts" / "runs" / "latest"
    assert latest.exists()  # symlink or text fallback


def test_record_command_writes_argv_and_shell(tmp_path: Path) -> None:
    rec = RunRecorder.start(
        workspace=tmp_path,
        requested_settings=Settings(),
        run_resolution=_rr(),
        host=_host(tmp_path),
        build_label="b",
        rootfs_label="r",
        profiles=_rr().profiles,
    )
    rec.record_command("qemu", shell="qemu-system-aarch64 ...", argv=["qemu-system-aarch64", "-M", "virt"])
    assert (rec.run_dir / "commands" / "qemu.sh").read_text().startswith("qemu-system-aarch64")
    assert json.loads((rec.run_dir / "commands" / "qemu.argv.json").read_text())[1] == "-M"


def test_set_status_appends_history(tmp_path: Path) -> None:
    rec = RunRecorder.start(
        workspace=tmp_path,
        requested_settings=Settings(),
        run_resolution=_rr(),
        host=_host(tmp_path),
        build_label="b",
        rootfs_label="r",
        profiles=_rr().profiles,
    )
    rec.set_status("launched")
    run = json.loads((rec.run_dir / "run.json").read_text())
    assert run["status"] == "launched"
    assert [h["status"] for h in run["status_history"]] == ["created", "launched"]


def test_recorder_exposes_console_and_crash_paths(tmp_path: Path) -> None:
    rec = _start_recorder(tmp_path)
    assert rec.console_raw == rec.run_dir / "logs" / "console.raw"
    assert rec.crash_dir == rec.run_dir / "crash"
    assert rec.crash_dir.is_dir()


def test_recorder_accepts_crashed_status(tmp_path: Path) -> None:
    rec = _start_recorder(tmp_path)
    rec.set_status("crashed", message="oops")
    rj = json.loads((rec.run_dir / "run.json").read_text())
    assert rj["status"] == "crashed"


def test_run_json_has_guest_block(tmp_path: Path) -> None:
    rec = _start_recorder(tmp_path)
    rj = json.loads((rec.run_dir / "run.json").read_text())
    g = rj["guest"]
    assert g["ssh_host"] == "127.0.0.1"
    assert g["ssh_port"] == 2222
    assert g["share_mount"] == "/mnt/exploit"
    assert g["share_dir"] == "exploit"
    assert rec.run_dir.joinpath("exploit").is_dir()


def test_run_json_omits_guest_block_when_guest_net_false(tmp_path: Path) -> None:
    rec = _start_recorder(tmp_path, effective_debuggee=DebuggeeCfg(guest_net=False))
    rj = json.loads((rec.run_dir / "run.json").read_text())
    assert "guest" not in rj
    assert rec.run_dir.joinpath("exploit").is_dir()
