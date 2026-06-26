from pathlib import Path
from types import SimpleNamespace

import pytest

import likedbg.cli as cli
from likedbg import cache
from likedbg.cache import Manifest
from likedbg.cache import build_recipe
from likedbg.cache import rootfs_recipe
from likedbg.cache import write_manifest
from likedbg.cli import _require_volume_for_adopt
from likedbg.cli import build_pipeline
from likedbg.cli import build_use_pipeline
from likedbg.cli import cmd_clean
from likedbg.cli import summarize_cache
from likedbg.config import ConfigResolution
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import ConfigError
from likedbg.errors import HostCapabilityError
from likedbg.errors import SessionError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.rootfs import rootfs_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _host(mode):
    return HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=mode,
        gdbstub_addr="localhost",
        ssh_addr="localhost",
    )


def _make_project(tmp_path: Path) -> None:
    """Minimal project layout with a default.toml and an exploit-dev profile."""
    cfgs = tmp_path / "configs"
    (cfgs / "fragments" / "profiles").mkdir(parents=True)
    (cfgs / "profiles").mkdir(parents=True)
    (cfgs / "default.toml").write_text('[source]\nkind="mmp"\nvalue="6.6.30"\n')
    (cfgs / "fragments" / "generic.config").write_text("CONFIG_X=y\n")
    (cfgs / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\n'
        'kind="base"\n'
        'description="d"\n'
        'fragments=["configs/fragments/generic.config"]\n'
    )


def _config_resolution(tmp_path: Path) -> ConfigResolution:
    """Return a real ConfigResolution built from a minimal temp project."""
    _make_project(tmp_path)
    from likedbg.config import load_config

    return load_config(tmp_path)


class _FakeSession:
    def __init__(self):
        self.options: list[tuple[str, str]] = []
        self.unset_options: list[str] = []
        self.pane_launches: list[dict[str, object]] = []
        self.pipe_pane_calls: list[dict[str, object]] = []
        self._panes = iter(["%2", "%3"])

    def current_pane_id(self) -> str:
        return "%1"

    def run_in_new_pane(self, *, target, direction, percent, cmd):
        pane = next(self._panes)
        self.pane_launches.append(
            {
                "target": target,
                "direction": direction,
                "percent": percent,
                "cmd": cmd,
                "pane": pane,
            }
        )
        return pane

    def set_option(self, name, value):
        self.options.append((name, value))

    def unset_option(self, name):
        self.unset_options.append(name)

    def pipe_pane(self, *, pane: str, output) -> None:
        self.pipe_pane_calls.append({"pane": pane, "output": output})


class _RestartSession:
    def __init__(self, *, options=None, existing=("%1", "%2", "%3"), active="%3"):
        self.options = dict(options or {})
        self.existing = set(existing)
        self.active = active
        self.sets: list[tuple[str, str]] = []
        self.unsets: list[str] = []
        self.respawns: list[tuple[str, str]] = []
        self.launches: list[dict[str, object]] = []
        self.selected: list[str] = []
        self.messages: list[str] = []

    def get_option(self, name):
        return self.options.get(name, "")

    def set_option(self, name, value):
        self.options[name] = value
        self.sets.append((name, value))

    def unset_option(self, name):
        self.options.pop(name, None)
        self.unsets.append(name)

    def current_pane_id(self):
        return self.active

    def pane_exists(self, pane):
        return pane in self.existing

    def respawn_pane(self, *, pane, cmd):
        self.respawns.append((pane, cmd))

    def run_in_new_pane(self, *, target, direction, percent, cmd):
        pane = "%4"
        self.existing.add(pane)
        self.launches.append({"target": target, "direction": direction, "percent": percent, "cmd": cmd, "pane": pane})
        return pane

    def select_pane(self, target):
        self.selected.append(target)

    def display_message(self, message):
        self.messages.append(message)

    def pipe_pane(self, *, pane: str, output) -> None:
        pass


class _FakeContainer(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


class _DuContainer(_FakeContainer):
    def __init__(self, output="8192\t/ksrc/linux-6.6.30-volume\n", *, fail=False):
        self.output = output
        self.fail = fail
        self.runs = []
        self.execs = []
        self.stopped = []

    def run_detached(self, image, **kwargs):
        handle = SimpleNamespace(id="du-helper")
        self.runs.append({"image": image, **kwargs})
        return handle

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if self.fail:
            raise RuntimeError("du unavailable")
        return SimpleNamespace(exit_code=0, output=self.output)

    def stop(self, container):
        self.stopped.append(container.id)


# ---------------------------------------------------------------------------
# Pipeline stage-order tests (migrated + updated for new stages)
# ---------------------------------------------------------------------------


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == [
        "download",
        "unpack",
        "build",
        "profile-verification",
        "rootfs",
        "export",
        "debuggee",
        "debugger",
    ]


def test_adopt_guard_rejects_bind():
    with pytest.raises(HostCapabilityError):
        _require_volume_for_adopt(_host("bind"))


def test_adopt_guard_accepts_volume():
    _require_volume_for_adopt(_host("volume"))  # no raise


def test_summarize_cache_empty(tmp_path):
    assert summarize_cache(tmp_path) == ["(cache empty)"]


def test_summarize_cache_lists_build_and_rootfs(tmp_path):
    write_manifest(
        tmp_path,
        Manifest(
            kind="build", label="linux-6.6.30-aaaa", key="k", version="6.6.30", arch="arm64", storage_mode="volume"
        ),
    )
    rimg = tmp_path / "artifacts" / "rootfs" / "rootfs-arm64-bookworm-cccc.img"
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"x" * 2048)
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label="rootfs-arm64-bookworm-cccc",
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(rimg)},
        ),
    )
    lines = summarize_cache(tmp_path)
    joined = "\n".join(lines)
    assert "linux-6.6.30-aaaa" in joined and "6.6.30" in joined
    assert "rootfs-arm64-bookworm-cccc" in joined
    assert "build" in joined and "rootfs" in joined


def test_summarize_cache_uses_bind_build_image_host_size(tmp_path):
    image = tmp_path / "artifacts" / "ksrc" / "linux-6.6.30-bind" / "arch" / "arm64" / "boot" / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 4096)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label="linux-6.6.30-bind",
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="bind",
            paths={"image_host": str(image)},
        ),
    )
    assert "4096" in "\n".join(summarize_cache(tmp_path))


def test_summarize_cache_preserves_legacy_volume_image_size_fallback(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume"),
    )
    assert "1024" in "\n".join(summarize_cache(tmp_path))


def test_summarize_cache_uses_volume_tree_du_when_container_available(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={"kernel_root": f"/ksrc/{label}", "image_host": str(image)},
        ),
    )
    container = _DuContainer(output=f"8192\t/ksrc/{label}\n")
    joined = "\n".join(summarize_cache(tmp_path, container=container))
    assert "8192" in joined
    assert "1024" not in joined
    assert container.runs[0]["volumes"]["likedbg_ksrc"]["bind"] == "/ksrc"
    assert container.runs[0]["volumes"]["likedbg_ksrc"]["mode"] == "ro"
    assert container.execs == [f"du -sb /ksrc/{label}"]
    assert container.stopped == ["du-helper"]


def test_summarize_cache_falls_back_when_volume_du_fails(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={"kernel_root": f"/ksrc/{label}", "image_host": str(image)},
        ),
    )
    assert "1024" in "\n".join(summarize_cache(tmp_path, container=_DuContainer(fail=True)))


def test_cmd_clean_unknown_label_raises(tmp_path):
    with pytest.raises(CacheError) as exc:
        cmd_clean(_FakeContainer(), tmp_path, label="nope", clean_all=False)
    assert "start_kgdb --list" in (exc.value.remedy or "")


def test_cmd_clean_all_removes_every_manifest(tmp_path):
    write_manifest(
        tmp_path,
        Manifest(
            kind="build", label="linux-6.6.30-aaaa", key="k", version="6.6.30", arch="arm64", storage_mode="volume"
        ),
    )
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label="rootfs-arm64-bookworm-cccc",
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(tmp_path / "gone.img")},
        ),
    )
    rc = cmd_clean(_FakeContainer(), tmp_path, label=None, clean_all=True)
    assert rc == 0
    assert cache.list_manifests(tmp_path, "build") == []
    assert cache.list_manifests(tmp_path, "rootfs") == []


def test_build_use_pipeline_includes_rootfs_before_launch(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    session = _FakeSession()
    pipe = build_use_pipeline(
        _FakeContainer(),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        gdb_mount_source="likedbg_ksrc",
        rootfs_recipe=rootfs_recipe(settings),
        recorder=None,
    )
    assert [s.name for s in pipe._stages] == [  # type: ignore[attr-defined]
        "profile-verification",
        "rootfs",
        "export",
        "debuggee",
        "debugger",
    ]


def _make_cmd_use_project(tmp_path: Path) -> None:
    """Create configs/default.toml so load_config succeeds in cmd_use tests."""
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "profiles").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.toml").write_text(
        '[source]\nkind="mmp"\nvalue="6.6.30"\n[general]\narch="arm64"\n'
    )
    (tmp_path / "configs" / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
    )


def test_cmd_use_builds_default_rootfs_when_manifest_is_missing(tmp_path, monkeypatch):
    _make_cmd_use_project(tmp_path)
    settings = Settings.model_validate(
        {"general": {"arch": "arm64"}, "debuggee": {"accel": "tcg", "network": "host"}}
    )
    rr = rootfs_recipe(settings)
    target = rootfs_target(tmp_path, rr.label)

    class RootfsContainer(_FakeContainer):
        def __init__(self):
            super().__init__()
            self.rootfs_runs = []

        def run_detached(self, image, **kwargs):
            self.rootfs_runs.append({"image": image, **kwargs})
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"img")
            return SimpleNamespace(id="rootfs", logs=lambda **k: iter([]))

    label = "linux-6.6.30-bind"
    kernel_image = tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot" / "Image"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="bind",
            paths={
                "kernel_root": f"/ksrc/{label}",
                "gdb_vmlinux": f"/ksrc/{label}/vmlinux",
                "image_host": str(kernel_image),
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
                "gdb_mount_source": str(tmp_path / "artifacts" / "ksrc"),
            },
        ),
    )
    container = RootfsContainer()
    # Monkeypatch load_config so it returns a ConfigResolution with the right settings.
    # We also patch HostProfile.detect, _ensure_images, add_run_logfile, and RunRecorder.start.
    from likedbg.config import load_config as real_load_config

    def fake_load_config(workspace, *, scenario=None, cli_overrides=None):
        cr = real_load_config(workspace, scenario=scenario, cli_overrides={"general": {"arch": "arm64"}})
        return cr

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host("bind")))
    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: None)
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: _FakeRecorder(
                workspace
            )
        ),
    )

    assert cli.cmd_use(container, _FakeSession(), tmp_path, custom_ini=None, label=label, rootfs_label=None) == 0
    assert cache.manifest_exists(tmp_path, "rootfs", rr.label)
    assert target.read_bytes() == b"img"
    # ProfileVerificationStage also calls run_detached (legacy fallback, BASE_IMAGE).
    # Assert privileged=True on the SPECIFIC rootfs-build run (image == ROOTFS_IMAGE).
    rootfs_build_runs = [r for r in container.rootfs_runs if r["image"] == cli.ROOTFS_IMAGE]
    assert len(rootfs_build_runs) == 1, "expected exactly one rootfs-build container run"
    assert rootfs_build_runs[0]["privileged"] is True


def test_cmd_use_ensures_images_after_host_detection(tmp_path, monkeypatch):
    _make_cmd_use_project(tmp_path)
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    rr = rootfs_recipe(settings)
    rimg = rootfs_target(tmp_path, rr.label)
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=rr.label,
            key=rr.key,
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(rimg)},
        ),
    )
    label = "linux-6.6.30-volume"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={
                "kernel_root": f"/ksrc/{label}",
                "gdb_vmlinux": f"/ksrc/{label}/vmlinux",
                "image_host": str(tmp_path / "artifacts" / label / "Image"),
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
                "gdb_mount_source": "likedbg_ksrc",
            },
        ),
    )
    specs_seen = []
    from likedbg.config import load_config as real_load_config

    def fake_load_config(workspace, *, scenario=None, cli_overrides=None):
        return real_load_config(workspace, scenario=scenario, cli_overrides={"general": {"arch": "arm64"}})

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host("volume")))
    monkeypatch.setattr(
        cli,
        "_ensure_images",
        lambda container, workspace, *, specs: specs_seen.append(tuple(s.tag for s in specs)),
    )
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: _FakeRecorder(
                workspace
            )
        ),
    )

    assert cli.cmd_use(_FakeContainer(), _FakeSession(), tmp_path, custom_ini=None, label=label, rootfs_label=None) == 0
    assert specs_seen == [tuple(s.tag for s in cli.images.required_for_use(_host("volume")))]


class _FakeRecorder:
    """Minimal RunRecorder stand-in for pipeline tests — mirrors the public RunRecorder API."""

    def __init__(self, workspace: Path) -> None:
        logs = workspace / "artifacts" / "runs" / "fake" / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        self.likedbg_log = logs / "likedbg.log"
        self.debuggee_pane_log = logs / "debuggee-pane.log"
        self.debugger_pane_log = logs / "debugger-pane.log"

    def add_warning(self, code: str, message: str) -> None:
        pass

    def record_profile_verification(self, verification: object) -> None:
        pass

    def record_kernel_paths(self, *, config, system_map, vmlinux, image) -> None:
        pass

    def set_status(self, status: str, *, message: str | None = None) -> None:
        pass

    def record_command(self, kind: str, *, shell: str, argv: list) -> None:
        pass


def test_pipeline_launches_process_panes_and_stores_session_options(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    recorder = _FakeRecorder(tmp_path)
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=recorder,
    )
    ctx = PipelineContext(settings=settings, host=_host("volume"), build_label=br.label, rootfs_label=rr.label)
    ctx.kernel_image = tmp_path / "artifacts" / br.label / "Image"
    ctx.rootfs_image = tmp_path / "artifacts" / "rootfs.img"
    ctx.vmlinux = tmp_path / "artifacts" / br.label / "vmlinux"

    # Run only the debuggee and debugger stages (indices -2 and -1)
    pipe._stages[-2].run(ctx)  # type: ignore[attr-defined]
    pipe._stages[-1].run(ctx)  # type: ignore[attr-defined]

    assert session.pane_launches[0]["target"] == "%1"
    assert session.pane_launches[0]["direction"] == "h"
    assert session.pane_launches[0]["percent"] == 66
    assert session.pane_launches[1]["target"] == "%2"
    assert session.pane_launches[1]["direction"] == "v"
    assert session.pane_launches[1]["percent"] == 50
    assert session.unset_options == [
        "@likedbg_restart_in_progress",
        "@likedbg_debuggee_cmd",
        "@likedbg_debugger_cmd",
        "@likedbg_debuggee_pane",
        "@likedbg_debugger_pane",
        "@likedbg_debuggee_pane_log",
    ]
    assert session.options[0:2] == [
        ("@likedbg_workspace", str(tmp_path)),
        ("@likedbg_base_pane_id", "%1"),
    ]
    options = dict(session.options)
    assert options["@likedbg_debuggee_cmd"] == session.pane_launches[0]["cmd"]
    assert options["@likedbg_debugger_cmd"] == session.pane_launches[1]["cmd"]
    assert options["@likedbg_debuggee_pane"] == "%2"
    assert options["@likedbg_debugger_pane"] == "%3"
    # New: transcript capture options set when recorder is provided
    assert options["@likedbg_debuggee_pane_log"] == str(recorder.debuggee_pane_log)
    assert any(c["pane"] == "%2" for c in session.pipe_pane_calls), "pipe_pane should have been called for debuggee"
    assert any(c["pane"] == "%3" for c in session.pipe_pane_calls), "pipe_pane should have been called for debugger"


# ---------------------------------------------------------------------------
# resolve_for_run tests
# ---------------------------------------------------------------------------


def test_resolve_for_run_unknown_profile_raises_and_creates_no_run_dir(tmp_path, monkeypatch):
    """Unknown profile must raise ConfigError BEFORE any run dir is created."""
    _make_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError):
        cli.resolve_for_run(tmp_path, profile_arg="asan", scenario=None, cli_overrides=None)
    # The run directory must NOT have been created.
    assert not (tmp_path / "artifacts" / "runs").exists()


def test_resolve_for_run_exploit_dev_resolves(tmp_path, monkeypatch):
    """Default exploit-dev profile resolves when a configs/profiles/exploit-dev.toml is present."""
    _make_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    cfg, host, rr = cli.resolve_for_run(tmp_path, profile_arg="exploit-dev", scenario=None, cli_overrides=None)
    assert "exploit-dev" in rr.profiles.names
    # No run dir should exist — resolve_for_run itself never creates one.
    assert not (tmp_path / "artifacts" / "runs").exists()


# ---------------------------------------------------------------------------
# Restart tests
# ---------------------------------------------------------------------------


def _restart_options():
    return {
        "@likedbg_workspace": "/ws",
        "@likedbg_base_pane_id": "%1",
        "@likedbg_debuggee_cmd": "qemu-system-aarch64 -S",
        "@likedbg_debuggee_pane": "%2",
    }


def test_restart_debuggee_respawns_existing_pane_in_place():
    session = _RestartSession(options=_restart_options())
    assert cli.cmd_restart_debuggee(session) == 0  # type: ignore[arg-type]
    assert session.sets[0] == ("@likedbg_restart_in_progress", "1")
    assert session.respawns == [("%2", "qemu-system-aarch64 -S")]
    assert session.launches == []
    assert session.selected == ["%3"]
    assert session.messages == [
        "LIKE-DBG Debuggee restarted; in GDB run likedbg-reconnect, not target remote localhost"
    ]
    assert "@likedbg_restart_in_progress" in session.unsets
    assert session.options["@likedbg_debuggee_pane"] == "%2"


def test_restart_debuggee_recreates_when_debuggee_pane_stale():
    session = _RestartSession(options=_restart_options(), existing=("%1", "%3"))
    assert cli.cmd_restart_debuggee(session) == 0  # type: ignore[arg-type]
    assert session.respawns == []
    assert session.launches == [
        {
            "target": "%1",
            "direction": "h",
            "percent": 66,
            "cmd": "qemu-system-aarch64 -S",
            "pane": "%4",
        }
    ]
    assert session.options["@likedbg_debuggee_pane"] == "%4"
    assert session.selected == ["%3"]
    assert session.messages == [
        "LIKE-DBG Debuggee restarted; in GDB run likedbg-reconnect, not target remote localhost"
    ]


def test_restart_debuggee_missing_command_or_workspace_raises_remedy():
    for missing in ("@likedbg_workspace", "@likedbg_debuggee_cmd"):
        options = _restart_options()
        options.pop(missing)
        with pytest.raises(SessionError) as exc:
            cli.cmd_restart_debuggee(_RestartSession(options=options))  # type: ignore[arg-type]
        assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_clears_lock_on_post_acquire_failure():
    options = _restart_options()
    options.pop("@likedbg_workspace")
    session = _RestartSession(options=options)
    with pytest.raises(SessionError):
        cli.cmd_restart_debuggee(session)  # type: ignore[arg-type]
    assert session.unsets[-1] == "@likedbg_restart_in_progress"
    assert "@likedbg_restart_in_progress" not in session.options


def test_restart_debuggee_missing_base_only_fatal_for_recreate():
    existing_debuggee = _RestartSession(options=_restart_options(), existing=("%2", "%3"))
    assert cli.cmd_restart_debuggee(existing_debuggee) == 0  # type: ignore[arg-type]

    missing_base = _RestartSession(options=_restart_options(), existing=("%3",))
    with pytest.raises(SessionError) as exc:
        cli.cmd_restart_debuggee(missing_base)  # type: ignore[arg-type]
    assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_lock_prevents_double_tap():
    options = _restart_options()
    options["@likedbg_restart_in_progress"] = "1"
    session = _RestartSession(options=options)
    with pytest.raises(SessionError) as exc:
        cli.cmd_restart_debuggee(session)  # type: ignore[arg-type]
    assert "already in progress" in str(exc.value)
    assert session.respawns == []
    assert session.launches == []
    assert session.unsets == []


def test_main_restart_bypasses_config_and_docker(monkeypatch):
    restarted = []
    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: pytest.fail("load_settings should not run"))
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: pytest.fail("docker should not run"))
    monkeypatch.setattr(cli, "cmd_restart_debuggee", lambda session: restarted.append(session) or 0)
    assert cli.main(["--restart-debuggee"]) == 0
    assert len(restarted) == 1


def test_main_restart_failure_displays_tmux_message(monkeypatch):
    created = []

    class FakeSession(_RestartSession):
        def __init__(self, name):
            super().__init__()
            self.name = name
            created.append(self)

    def fail_restart(session):
        raise SessionError("missing @likedbg_debuggee_cmd", remedy="start fresh")

    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "Session", FakeSession)
    monkeypatch.setattr(cli, "cmd_restart_debuggee", fail_restart)
    assert cli.main(["--restart-debuggee"]) == 1
    assert created[0].messages == ["LIKE-DBG restart failed: missing @likedbg_debuggee_cmd"]


def test_main_restart_requires_tmux(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: pytest.fail("load_settings should not run"))
    assert cli.main(["--restart-debuggee"]) == 2


def test_main_build_images_is_docker_only_and_invokes_build_images(monkeypatch):
    built = []
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.images, "build_images", lambda container, workspace, *a, **k: built.append(True))
    monkeypatch.delenv("TMUX", raising=False)  # build-images must NOT require tmux

    assert cli.main(["--build-images"]) == 0
    assert built == [True]


def test_ensure_images_helper_warns_each_stale_tag(monkeypatch):
    monkeypatch.setattr(cli.images, "ensure_current", lambda container, workspace, specs: ["like_rootfs:latest"])
    msgs = []
    monkeypatch.setattr(cli.logger, "warning", lambda msg: msgs.append(msg))
    cli._ensure_images(object(), object(), specs=())
    assert len(msgs) == 1
    assert "like_rootfs:latest" in msgs[0]
    assert "--build-images" in msgs[0]


def test_main_configures_stderr_always_but_logfile_only_for_runs(monkeypatch):
    calls = {"stderr": 0, "logfile": 0}
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.logsetup, "configure_stderr", lambda **k: calls.__setitem__("stderr", calls["stderr"] + 1))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda ws: calls.__setitem__("logfile", calls["logfile"] + 1))
    monkeypatch.setattr(cli, "summarize_cache", lambda ws, **kwargs: ["(cache empty)"])

    assert cli.main(["--list"]) == 0
    assert calls["stderr"] == 1  # configure_stderr runs for every invocation
    assert calls["logfile"] == 0  # --list writes no run log file
