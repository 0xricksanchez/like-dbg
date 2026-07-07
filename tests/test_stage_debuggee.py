from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debuggee import DebuggeeStage


def _ctx(mode):
    arch = "arm64" if mode == "native-host" else "x86_64"
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=arch,
        accel="hvf" if mode == "native-host" else "tcg",
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": arch}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/x/Image")
    return ctx


def test_native_debuggee_sends_plain_qemu_argv(tmp_path):
    launched = {}
    DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    ).run(_ctx("native-host"))
    assert launched["cmd"].startswith("qemu-system-aarch64")
    assert "docker run" not in launched["cmd"]


def test_in_container_debuggee_wraps_docker_run(tmp_path):
    launched = {}
    DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    ).run(_ctx("in-container"))
    assert launched["cmd"].startswith("docker run --rm -it -p 1234:1234")
    assert "like_debuggee:latest" in launched["cmd"]
    assert "qemu-system-x86_64" in launched["cmd"]
    assert "-v /ws/artifacts/x/Image:/ws/artifacts/x/Image:ro" in launched["cmd"]


def _linux_ctx(*, accel="tcg"):
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel=accel,
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
        network_mode="host",
    )
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": "arm64"}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/ksrc/x/arch/arm64/boot/Image")
    ctx.rootfs_image = Path("/ws/artifacts/rootfs/r.img")
    return ctx


def test_linux_in_container_uses_host_network(tmp_path):
    launched = {}
    DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    ).run(_linux_ctx())
    assert "--network host" in launched["cmd"]
    assert "-p 1234:1234" not in launched["cmd"]
    assert "/dev/kvm" not in launched["cmd"]  # tcg → no kvm device


def test_linux_kvm_passes_device(tmp_path):
    launched = {}
    DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    ).run(_linux_ctx(accel="kvm"))
    assert "--device /dev/kvm" in launched["cmd"]


class _Rec:
    def __init__(self):
        self.statuses = []
        self.cmds = []
        self.console_raw = Path("/ws/run/logs/console.raw")

    def set_status(self, s, *, message=None):
        self.statuses.append(s)

    def record_command(self, kind, *, shell, argv):
        self.cmds.append((kind, argv))

    def add_warning(self, *a, **k):
        pass


def test_debuggee_records_command_and_status(tmp_path):
    launched = {}
    stage = DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    )
    rec = _Rec()
    ctx = _ctx("native-host")
    ctx.recorder = rec
    stage.run(ctx)
    assert len(rec.cmds) == 1
    assert rec.cmds[0][0] == "qemu"
    assert "launching" in rec.statuses


def test_debuggee_records_launch_failed_on_exception(tmp_path):
    def _raise(cmd):
        raise RuntimeError("boom")

    rec = _Rec()
    stage = DebuggeeStage(launch=_raise, debuggee_image="like_debuggee:latest", workspace=tmp_path)
    ctx = _ctx("native-host")
    ctx.recorder = rec
    try:
        stage.run(ctx)
    except RuntimeError:
        pass
    assert "launch-failed" in rec.statuses


def test_debuggee_no_recorder_still_launches(tmp_path):
    launched = {}
    stage = DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd),
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    )
    ctx = _ctx("native-host")
    # recorder is None by default
    stage.run(ctx)
    assert "cmd" in launched


def test_debuggee_threads_share_and_ssh_port(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "likedbg.stages.debuggee.build_qemu_argv",
        lambda *a, **k: captured.update(k) or ["qemu"],
    )
    stage = DebuggeeStage(
        launch=lambda cmd: None,
        debuggee_image="like_debuggee:latest",
        workspace=tmp_path,
    )
    ctx = _ctx("native-host")
    stage.run(ctx)
    assert captured["share_host_dir"] == tmp_path / "exploit"
    assert (tmp_path / "exploit").is_dir()


def test_debuggee_threads_foreign_cmdline_and_qemu_extra(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "likedbg.stages.debuggee.build_qemu_argv",
        lambda *a, **k: captured.update(k) or ["qemu-system-x86_64"],
    )
    ctx = _ctx("native-host")
    ctx.foreign_cmdline = "quiet console=ttyS0"
    ctx.qemu_extra = ("-no-reboot",)
    DebuggeeStage(launch=lambda cmd: None, debuggee_image="like_debuggee:latest", workspace=tmp_path).run(ctx)
    assert captured["foreign_cmdline"] == "quiet console=ttyS0"
    assert captured["qemu_extra"] == ("-no-reboot",)
