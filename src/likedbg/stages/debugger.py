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
        args = build_gdb_args(
            ctx.host,
            arch=ctx.settings.general.arch,
            vmlinux=ctx.vmlinux,
            ext=self._ext,
            breakpoint=self._breakpoint,
            port=ctx.settings.debuggee.gdb_port,
        )
        self._run_gdb(args)
        return ctx
