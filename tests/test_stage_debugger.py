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
