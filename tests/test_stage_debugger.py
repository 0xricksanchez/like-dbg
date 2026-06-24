from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debugger import DebuggerStage


def _ctx():
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
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
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
        ssh_addr="localhost",
        network_mode="host",
    )
    ctx = PipelineContext(settings=settings, host=host)
    ctx.vmlinux = Path("/ksrc/x/vmlinux")
    DebuggerStage(ext="gef", run_gdb=lambda args: captured.setdefault("args", args), breakpoint=None).run(ctx)
    assert "gef-remote localhost 4444" in " ".join(captured["args"])
