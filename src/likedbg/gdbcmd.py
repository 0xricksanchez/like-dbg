"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.host_profile import HostProfile

# Both extensions are installed in the debugger image; exactly one is sourced per run
# (gef and pwndbg conflict if both load). ~/.gdbinit no longer auto-loads either —
# the requested extension is sourced explicitly here.
_EXT_SOURCE = {"gef": "/opt/gef/gef.py", "pwndbg": "/opt/pwndbg/gdbinit.py"}

_GDB_ARCH = {"arm64": "aarch64", "x86_64": "i386:x86-64"}


def _remote_command(ext: str, addr: str, port: int) -> str:
    if ext == "gef":
        return f"gef-remote {addr} {port}"
    return f"target remote {addr}:{port}"


def _reconnect_helper(ext: str, addr: str, port: int, breakpoint: str | None) -> str:
    reconnect = _remote_command(ext, addr, port)
    breakpoint_literal = repr(breakpoint)
    source = f"""
import gdb


def _show_pwndbg_context_sections():
    try:
        import pwndbg

        return str(pwndbg.config.context_sections)
    except Exception:
        return None


def _set_pwndbg_context_sections(value):
    if value is None:
        return
    try:
        import pwndbg

        pwndbg.config.context_sections.value = value
    except Exception:
        try:
            if value == "":
                gdb.execute("set context-sections ''", to_string=True)
            else:
                gdb.execute("set context-sections " + value, to_string=True)
        except gdb.error:
            pass


def _breakpoint_exists(spec):
    for bp in gdb.breakpoints() or []:
        if getattr(bp, "location", None) == spec and getattr(bp, "enabled", True):
            return True
    return False


class LikedbgReconnect(gdb.Command):
    def __init__(self):
        super().__init__("likedbg-reconnect", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        context_sections = _show_pwndbg_context_sections()
        try:
            _set_pwndbg_context_sections("")
            try:
                gdb.execute("disconnect", to_string=True)
            except gdb.error:
                pass
            gdb.execute({reconnect!r}, from_tty=from_tty)
            breakpoint = {breakpoint_literal}
            if breakpoint is not None:
                if not _breakpoint_exists(breakpoint):
                    gdb.execute("hbreak " + breakpoint, from_tty=from_tty)
                gdb.execute("continue", from_tty=from_tty)
        finally:
            _set_pwndbg_context_sections(context_sections)


LikedbgReconnect()
"""
    return f"python exec({source!r})"


def _crash_capture_source(symbols: tuple[str, ...], out_path: str) -> str:
    # Built via literal placeholder substitution (not %-formatting or f-string
    # interpolation) so the payload's own `%s` formatting and `{}` dict/set
    # literals below can be written as plain, unescaped Python source.
    source = """
import gdb, json, os

_OUT = __OUT__
_SYMS = __SYMS__


def _regs():
    out = {}
    try:
        frame = gdb.selected_frame()
        for reg in frame.architecture().registers():
            try:
                out[reg.name] = str(frame.read_register(reg.name))
            except Exception:
                pass
    except Exception:
        pass
    return out


def _bt():
    try:
        return gdb.execute("bt", to_string=True).splitlines()
    except Exception:
        return []


class _LikedbgCrash(gdb.Breakpoint):
    def stop(self):
        try:
            os.makedirs(os.path.dirname(_OUT), exist_ok=True)
            with open(_OUT, "w") as fh:
                json.dump({"stopped_at": self.location, "registers": _regs(), "backtrace": _bt()}, fh, indent=2)
            gdb.write("[likedbg] crash captured at %s -> %s\\n" % (self.location, _OUT))
        except Exception as exc:
            gdb.write("[likedbg] crash capture failed: %s\\n" % exc)
        return True


for _s in _SYMS:
    try:
        _LikedbgCrash(_s)
    except Exception:
        pass
"""
    source = source.replace("__OUT__", repr(out_path)).replace("__SYMS__", repr(list(symbols)))
    return f"python exec({source!r})"


def build_gdb_args(
    host: HostProfile,
    *,
    arch: str,
    vmlinux: Path,
    ext: str,
    breakpoint: str | None,
    port: int = 1234,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
    crash_drop_path: str = CRASH_DROP_MOUNT,
) -> list[str]:
    addr = host.gdbstub_addr
    gdb_arch = _GDB_ARCH.get(arch)
    if gdb_arch is None:
        raise ValueError(f"unsupported gdb architecture: {arch}")
    # Source the chosen extension and enable auto-load BEFORE the symbol file loads
    # (mirrors ~/.gdbinit): the kernel's vmlinux-gdb.py / lx- helpers and the gef/pwndbg
    # hooks must be in place first (a later -ex is too late).
    args = ["gdb-multiarch", "-q"]
    args += ["-iex", f"source {_EXT_SOURCE[ext]}"]
    args += ["-iex", "set auto-load safe-path /", str(vmlinux)]
    args += ["-ex", f"set architecture {gdb_arch}"]
    args += ["-ex", _reconnect_helper(ext, addr, port, breakpoint)]
    args += ["-ex", _remote_command(ext, addr, port)]
    if breakpoint is not None:
        # Hardware breakpoint: a software `break` cannot be written to the kernel's
        # high-half virtual address before the MMU is enabled at early boot (e.g.
        # start_kernel) — validated live during the Plan 3 PoC.
        args += ["-ex", f"hbreak {breakpoint}", "-ex", "continue"]
    if break_on_crash and crash_breakpoints:
        # The crash breakpoints are SOFTWARE breakpoints on high-half kernel VAs
        # (panic/die/oops_enter). gdb inserts breakpoints on RESUME, so these must
        # be *created* only after the guest has reached start_kernel (kernel VA
        # space now mapped) — creating them before the initial `continue` makes
        # gdb try to insert them from CPU reset (MMU off) and abort the command,
        # so the guest never boots (arm64 live gate). Deferring their creation to
        # here means insertion happens on the user's next `continue`, when the VA
        # is up — exactly like a runtime `break schedule`.
        args += ["-ex", _crash_capture_source(crash_breakpoints, f"{crash_drop_path}/crash.gdb.json")]
    return args
