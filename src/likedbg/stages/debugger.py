"""Debugger stage: attach containerized gdb to the QEMU gdbstub."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.gdbcmd import build_gdb_args
from likedbg.pipeline import PipelineContext


class DebuggerStage:
    name = "debugger"

    def __init__(
        self,
        *,
        ext: str,
        run_gdb: Callable[[list[str]], None],
        breakpoint: str | None,
        break_on_crash: bool = False,
        crash_breakpoints: tuple[str, ...] = (),
        sanitizer_breakpoints: tuple[str, ...] = (),
        modules_gdb: str | None = None,
        debuginfod_enabled: bool = False,
        debuginfod_urls: str = "",
    ) -> None:
        self._ext = ext
        self._run_gdb = run_gdb
        self._breakpoint = breakpoint
        self._break_on_crash = break_on_crash
        self._crash_breakpoints = crash_breakpoints
        self._sanitizer_breakpoints = sanitizer_breakpoints
        self._modules_gdb = modules_gdb
        self._debuginfod_enabled = debuginfod_enabled
        self._debuginfod_urls = debuginfod_urls

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.vmlinux is None:
            raise BuildError("no vmlinux in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        crash_dir = getattr(ctx.recorder, "crash_dir", None)
        args = build_gdb_args(
            ctx.host,
            arch=ctx.host.target_arch,
            vmlinux=ctx.vmlinux,
            ext=self._ext,
            breakpoint=self._breakpoint,
            port=eff.gdbstub_port,
            break_on_crash=self._break_on_crash,
            crash_breakpoints=self._crash_breakpoints,
            sanitizer_breakpoints=self._sanitizer_breakpoints,
            modules_gdb=self._modules_gdb,
            debuginfod_enabled=self._debuginfod_enabled,
            debuginfod_urls=self._debuginfod_urls,
            crash_display_path=str(crash_dir) if crash_dir is not None else None,
        )
        if ctx.recorder is not None:
            ctx.recorder.record_command("gdb", shell=" ".join(args), argv=args)
        try:
            self._run_gdb(args)
        except Exception:
            if ctx.recorder is not None:
                ctx.recorder.set_status("launch-failed", message="debugger launch failed")
            raise
        if ctx.recorder is not None:
            ctx.recorder.set_status("launched")
        return ctx
