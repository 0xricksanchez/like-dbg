"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

import inspect
import textwrap
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


def _reconcile_modules(
    log_text: str, applied: dict[str, tuple[str, str, tuple[tuple[str, str], ...]]]
) -> tuple[list[tuple[str, str, str, list[tuple[str, str]]]], list[tuple[str, str]]]:
    """Compute (adds, removes) to bring `applied` (name->(ko,text,secs)) in line with the lifecycle log.

    Pure python so it is unit-testable outside gdb. Events: 'load <name> <ko> <text> [<sec> <addr>...]'
    and 'unload <name>'. Returns (adds, removes); mutates `applied` to the post-apply state.

    The identity used for change-detection is the FULL (ko, text, secs) tuple, not just (ko, text):
    a reload at the same base address with a changed section list (e.g. new .data/.bss addresses
    after a rebuild, plausible under no-KASLR) must still trigger a remove+add, not a silent no-op.

    NOTE: this function's source is inlined verbatim into the gdb-python stop-hook payload built by
    `_module_symbols_source` (via `inspect.getsource`), so it and the in-gdb reconcile logic never
    drift apart. Keep it self-contained (module-level names only: no closures over gdbcmd internals).
    """
    desired: dict[str, tuple[str, str, list[tuple[str, str]]]] = {}
    for line in log_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "load" and len(parts) >= 4:
            name, ko, text = parts[1], parts[2], parts[3]
            secs = list(zip(parts[4::2], parts[5::2], strict=False))
            desired[name] = (ko, text, secs)
        elif parts[0] == "unload" and len(parts) >= 2:
            desired.pop(parts[1], None)
    adds: list[tuple[str, str, str, list[tuple[str, str]]]] = []
    removes: list[tuple[str, str]] = []
    for name, (ko, text, secs) in desired.items():
        if applied.get(name) != (ko, text, tuple(secs)):
            if name in applied:
                removes.append((name, applied[name][0]))
            adds.append((name, ko, text, secs))
    removes.extend((name, applied[name][0]) for name in applied if name not in desired)
    applied.clear()
    applied.update({n: (ko, text, tuple(secs)) for n, (ko, text, secs) in desired.items()})
    return adds, removes


def _module_symbols_source(modules_gdb_path: str) -> str:
    # Inline the pure `_reconcile_modules` source (dedented, renamed to `_reconcile`) so the payload's
    # reconcile logic and the unit-tested pure function are literally the same code — no drift between
    # what pytest exercises and what gdb executes. Placeholder substitution (not f-string/%-formatting),
    # same rationale as `_crash_capture_source`: the inlined body's own `%s`/`{}` must survive unescaped.
    reconcile_def = textwrap.dedent(inspect.getsource(_reconcile_modules)).replace("_reconcile_modules", "_reconcile")
    source = """
import gdb

_LOG = __LOG__
_APPLIED = {}

__RECONCILE_DEF__

def _sync(evt=None):
    try:
        try:
            with open(_LOG) as fh:
                text = fh.read()
        except OSError:
            return
        adds, removes = _reconcile(text, _APPLIED)
        for name, ko in removes:
            try:
                gdb.execute("remove-symbol-file " + ko, to_string=True)
            except Exception:
                pass
        for name, ko, text_addr, secs in adds:
            cmd = "add-symbol-file " + ko + " " + text_addr
            for sec, addr in secs:
                cmd += " -s " + sec + " " + addr
            try:
                gdb.execute(cmd, to_string=True)
                gdb.write("[likedbg] symbols: %s\\n" % name)
            except Exception as exc:
                gdb.write("[likedbg] add-symbol-file failed for %s: %s\\n" % (name, exc))
    except Exception as exc:
        gdb.write("[likedbg] module-sync error: %s\\n" % exc)


gdb.events.stop.connect(_sync)
"""
    source = source.replace("__LOG__", repr(modules_gdb_path)).replace("__RECONCILE_DEF__", reconcile_def)
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
    modules_gdb: str | None = None,
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
        # start_kernel).
        args += ["-ex", f"hbreak {breakpoint}", "-ex", "continue"]
    if break_on_crash and crash_breakpoints:
        # The crash breakpoints are SOFTWARE breakpoints on high-half kernel VAs
        # (panic/die/oops_enter). gdb inserts breakpoints on resume, so they must be
        # *created* only after the guest reaches start_kernel (kernel VA space now
        # mapped): creating them before the initial `continue` makes gdb try to insert
        # them from CPU reset (MMU off) and abort the command, so the guest never boots.
        # Deferring creation to here means insertion happens on the user's next
        # `continue`, when the VA is up, like a runtime `break schedule`.
        args += ["-ex", _crash_capture_source(crash_breakpoints, f"{crash_drop_path}/crash.gdb.json")]
    if modules_gdb is not None:
        # Stop-driven reconcile: fires on every gdb stop (breakpoints, signals, manual interrupt),
        # never on its own — loads/reloads/unloads module symbols non-disruptively at the operator's
        # next stop instead of interrupting a running target.
        args += ["-ex", _module_symbols_source(modules_gdb)]
    return args
