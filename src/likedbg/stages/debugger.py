"""Debugger stage: attach containerized gdb to the QEMU gdbstub."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.gdbcmd import build_gdb_args
from likedbg.pipeline import PipelineContext


class DebuggerStage:
    name = "debugger"

    def __init__(self, *, ext: str, run_gdb: Callable[[list[str]], None], breakpoint: str | None) -> None:
        self._ext = ext
        self._run_gdb = run_gdb
        self._breakpoint = breakpoint

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.vmlinux is None:
            raise BuildError("no vmlinux in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        args = build_gdb_args(
            ctx.host,
            arch=ctx.host.target_arch,
            vmlinux=ctx.vmlinux,
            ext=self._ext,
            breakpoint=self._breakpoint,
            port=eff.gdb_port,
        )
        if ctx.recorder is not None:
            ctx.recorder.record_command("gdb", shell=" ".join(args), argv=args)  # type: ignore[attr-defined]
        try:
            self._run_gdb(args)
        except Exception:
            if ctx.recorder is not None:
                ctx.recorder.set_status("launch-failed", message="debugger launch failed")  # type: ignore[attr-defined]
            raise
        if ctx.recorder is not None:
            ctx.recorder.set_status("launched")  # type: ignore[attr-defined]
        return ctx
