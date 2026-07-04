from pathlib import Path
from unittest.mock import MagicMock

from likedbg.config import DebuggeeCfg
from likedbg.stages.debugger import DebuggerStage


def test_debugger_stage_passes_crash_config(monkeypatch):
    captured = {}

    def fake_build(*a, **k):
        captured.update(k)
        return ["gdb-multiarch"]

    monkeypatch.setattr("likedbg.stages.debugger.build_gdb_args", fake_build)
    stage = DebuggerStage(
        ext="pwndbg",
        run_gdb=lambda args: None,
        breakpoint="start_kernel",
        break_on_crash=True,
        crash_breakpoints=("panic", "die"),
    )
    ctx = MagicMock()
    ctx.vmlinux = Path("/w/vmlinux")
    ctx.host.target_arch = "x86_64"
    ctx.effective_debuggee = DebuggeeCfg()
    ctx.recorder = None
    stage.run(ctx)
    assert captured["break_on_crash"] is True
    assert captured["crash_breakpoints"] == ("panic", "die")
