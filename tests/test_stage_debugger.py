from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debugger import DebuggerStage


def _ctx():
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": "arm64"}}), host=host)
    ctx.vmlinux = Path("/ws/artifacts/linux-6.6.30/vmlinux")
    return ctx


def test_debugger_builds_and_runs_gdb_with_breakpoint():
    ran = {}
    stage = DebuggerStage(ext="gef", run_gdb=lambda args: ran.setdefault("args", args), breakpoint="start_kernel")
    stage.run(_ctx())
    s = " ".join(ran["args"])
    assert "gef-remote host.docker.internal 1234" in s and "break start_kernel" in s
    assert "set architecture aarch64" in s


def test_debugger_threads_custom_gdb_port():
    captured = {}
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "debuggee": {"gdb_port": 4444}})
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
        network_mode="host",
    )
    ctx = PipelineContext(settings=settings, host=host)
    ctx.vmlinux = Path("/ksrc/x/vmlinux")
    DebuggerStage(ext="gef", run_gdb=lambda args: captured.setdefault("args", args), breakpoint=None).run(ctx)
    assert "gef-remote localhost 4444" in " ".join(captured["args"])


class _Rec:
    def __init__(self):
        self.statuses = []
        self.cmds = []

    def set_status(self, s, *, message=None):
        self.statuses.append(s)

    def record_command(self, kind, *, shell, argv):
        self.cmds.append((kind, argv))

    def add_warning(self, *a, **k):
        pass


def test_debugger_records_command_and_launched_status():
    ran = {}
    rec = _Rec()
    stage = DebuggerStage(ext="gef", run_gdb=lambda args: ran.setdefault("args", args), breakpoint=None)
    ctx = _ctx()
    ctx.recorder = rec
    stage.run(ctx)
    assert len(rec.cmds) == 1
    assert rec.cmds[0][0] == "gdb"
    assert "launched" in rec.statuses


def test_debugger_records_launch_failed_on_exception():
    def _raise(args):
        raise RuntimeError("boom")

    rec = _Rec()
    stage = DebuggerStage(ext="gef", run_gdb=_raise, breakpoint=None)
    ctx = _ctx()
    ctx.recorder = rec
    try:
        stage.run(ctx)
    except RuntimeError:
        pass
    assert "launch-failed" in rec.statuses
    assert "launched" not in rec.statuses


def test_debugger_stage_threads_modules_gdb_to_build_gdb_args(monkeypatch):
    captured = {}

    def fake_build(*a, **k):
        captured.update(k)
        return ["gdb-multiarch"]

    monkeypatch.setattr("likedbg.stages.debugger.build_gdb_args", fake_build)
    stage = DebuggerStage(
        ext="pwndbg", run_gdb=lambda args: None, breakpoint="start_kernel", modules_gdb="/exploit/modules.gdb"
    )
    stage.run(_ctx())
    assert captured["modules_gdb"] == "/exploit/modules.gdb"


def test_debugger_stage_threads_run_scoped_crash_display_path(monkeypatch, tmp_path):
    captured = {}

    def fake_build(*a, **k):
        captured.update(k)
        return ["gdb-multiarch"]

    class _Recorder:
        crash_dir = tmp_path / "artifacts" / "runs" / "run-123" / "crash"

        def record_command(self, *a, **k):
            pass

        def set_status(self, *a, **k):
            pass

    monkeypatch.setattr("likedbg.stages.debugger.build_gdb_args", fake_build)
    ctx = _ctx()
    ctx.recorder = _Recorder()
    DebuggerStage(ext="pwndbg", run_gdb=lambda args: None, breakpoint=None).run(ctx)
    assert captured["crash_display_path"] == str(_Recorder.crash_dir)


def test_debugger_stage_modules_gdb_defaults_to_none(monkeypatch):
    captured = {}

    def fake_build(*a, **k):
        captured.update(k)
        return ["gdb-multiarch"]

    monkeypatch.setattr("likedbg.stages.debugger.build_gdb_args", fake_build)
    DebuggerStage(ext="pwndbg", run_gdb=lambda args: None, breakpoint=None).run(_ctx())
    assert captured["modules_gdb"] is None
