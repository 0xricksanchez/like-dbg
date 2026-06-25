from types import SimpleNamespace

import pytest

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
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import HostCapabilityError
from likedbg.errors import SessionError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext


class _FakeSession:
    def __init__(self):
        self.options: list[tuple[str, str]] = []
        self.unset_options: list[str] = []
        self.pane_launches: list[dict[str, object]] = []
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


class _FakeContainer(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
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
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]


def _host(mode):
    return HostProfile(
        os="linux",
        host_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=mode,
        gdbstub_addr="localhost",
        ssh_addr="localhost",
    )


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


def test_build_use_pipeline_is_launch_only(tmp_path):
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
    )
    assert [s.name for s in pipe._stages] == ["export", "debuggee", "debugger"]  # type: ignore[attr-defined]


def test_pipeline_launches_process_panes_and_stores_session_options(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
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
    )
    ctx = PipelineContext(settings=settings, host=_host("volume"), build_label=br.label, rootfs_label=rr.label)
    ctx.kernel_image = tmp_path / "artifacts" / br.label / "Image"
    ctx.rootfs_image = tmp_path / "artifacts" / "rootfs.img"
    ctx.vmlinux = tmp_path / "artifacts" / br.label / "vmlinux"

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


def _restart_options():
    return {
        "@likedbg_workspace": "/ws",
        "@likedbg_base_pane_id": "%1",
        "@likedbg_debuggee_cmd": "qemu-system-aarch64 -S",
        "@likedbg_debuggee_pane": "%2",
    }


def test_restart_debuggee_respawns_existing_pane_in_place():
    import likedbg.cli as cli

    session = _RestartSession(options=_restart_options())
    assert cli.cmd_restart_debuggee(session) == 0  # type: ignore[arg-type]
    assert session.sets[0] == ("@likedbg_restart_in_progress", "1")
    assert session.respawns == [("%2", "qemu-system-aarch64 -S")]
    assert session.launches == []
    assert session.selected == ["%3"]
    assert session.messages == ["LIKE-DBG Debuggee restarted; run likedbg-reconnect in GDB"]
    assert "@likedbg_restart_in_progress" in session.unsets
    assert session.options["@likedbg_debuggee_pane"] == "%2"


def test_restart_debuggee_recreates_when_debuggee_pane_stale():
    import likedbg.cli as cli

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
    assert session.messages == ["LIKE-DBG Debuggee restarted; run likedbg-reconnect in GDB"]


def test_restart_debuggee_missing_command_or_workspace_raises_remedy():
    import likedbg.cli as cli

    for missing in ("@likedbg_workspace", "@likedbg_debuggee_cmd"):
        options = _restart_options()
        options.pop(missing)
        with pytest.raises(SessionError) as exc:
            cli.cmd_restart_debuggee(_RestartSession(options=options))  # type: ignore[arg-type]
        assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_clears_lock_on_post_acquire_failure():
    import likedbg.cli as cli

    options = _restart_options()
    options.pop("@likedbg_workspace")
    session = _RestartSession(options=options)
    with pytest.raises(SessionError):
        cli.cmd_restart_debuggee(session)  # type: ignore[arg-type]
    assert session.unsets[-1] == "@likedbg_restart_in_progress"
    assert "@likedbg_restart_in_progress" not in session.options


def test_restart_debuggee_missing_base_only_fatal_for_recreate():
    import likedbg.cli as cli

    existing_debuggee = _RestartSession(options=_restart_options(), existing=("%2", "%3"))
    assert cli.cmd_restart_debuggee(existing_debuggee) == 0  # type: ignore[arg-type]

    missing_base = _RestartSession(options=_restart_options(), existing=("%3",))
    with pytest.raises(SessionError) as exc:
        cli.cmd_restart_debuggee(missing_base)  # type: ignore[arg-type]
    assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_lock_prevents_double_tap():
    import likedbg.cli as cli

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
    import likedbg.cli as cli

    restarted = []
    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: pytest.fail("load_settings should not run"))
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: pytest.fail("docker should not run"))
    monkeypatch.setattr(cli, "cmd_restart_debuggee", lambda session: restarted.append(session) or 0)
    assert cli.main(["--restart-debuggee"]) == 0
    assert len(restarted) == 1


def test_main_restart_failure_displays_tmux_message(monkeypatch):
    import likedbg.cli as cli

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
    import likedbg.cli as cli

    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: pytest.fail("load_settings should not run"))
    assert cli.main(["--restart-debuggee"]) == 2


def test_main_build_images_is_docker_only_and_invokes_build_images(monkeypatch):
    import likedbg.cli as cli

    built = []
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.images, "build_images", lambda container, workspace, *a, **k: built.append(True))
    monkeypatch.delenv("TMUX", raising=False)  # build-images must NOT require tmux

    assert cli.main(["--build-images"]) == 0
    assert built == [True]


def test_ensure_images_helper_warns_each_stale_tag(monkeypatch):
    import likedbg.cli as cli

    monkeypatch.setattr(cli.images, "ensure_current", lambda container, workspace, specs: ["like_rootfs:latest"])
    msgs = []
    monkeypatch.setattr(cli.logger, "warning", lambda msg: msgs.append(msg))
    cli._ensure_images(object(), object(), specs=())
    assert len(msgs) == 1
    assert "like_rootfs:latest" in msgs[0]
    assert "--build-images" in msgs[0]


def test_main_configures_stderr_always_but_logfile_only_for_runs(monkeypatch):
    import likedbg.cli as cli

    calls = {"stderr": 0, "logfile": 0}
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.logsetup, "configure_stderr", lambda **k: calls.__setitem__("stderr", calls["stderr"] + 1))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda ws: calls.__setitem__("logfile", calls["logfile"] + 1))
    monkeypatch.setattr(cli, "summarize_cache", lambda ws: ["(cache empty)"])

    assert cli.main(["--list"]) == 0
    assert calls["stderr"] == 1  # configure_stderr runs for every invocation
    assert calls["logfile"] == 0  # --list writes no run log file
