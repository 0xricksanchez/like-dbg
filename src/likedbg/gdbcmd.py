"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

from pathlib import Path

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


def _reconnect_helper(ext: str, addr: str, port: int) -> str:
    reconnect = _remote_command(ext, addr, port)
    source = f"""
import gdb


class LikedbgReconnect(gdb.Command):
    def __init__(self):
        super().__init__("likedbg-reconnect", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            gdb.execute("disconnect", to_string=True)
        except gdb.error:
            pass
        gdb.execute({reconnect!r}, from_tty=from_tty)


LikedbgReconnect()
"""
    return f"python exec({source!r})"


def build_gdb_args(
    host: HostProfile, *, arch: str, vmlinux: Path, ext: str, breakpoint: str | None, port: int = 1234
) -> list[str]:
    addr = host.gdbstub_addr
    # Source the chosen extension and enable auto-load BEFORE the symbol file loads
    # (mirrors ~/.gdbinit): the kernel's vmlinux-gdb.py / lx- helpers and the gef/pwndbg
    # hooks must be in place first (a later -ex is too late).
    args = ["gdb-multiarch", "-q"]
    args += ["-iex", f"source {_EXT_SOURCE[ext]}"]
    args += ["-iex", "set auto-load safe-path /", str(vmlinux)]
    args += ["-ex", f"set architecture {_GDB_ARCH[arch]}"]
    args += ["-ex", _reconnect_helper(ext, addr, port)]
    args += ["-ex", _remote_command(ext, addr, port)]
    if breakpoint is not None:
        # Hardware breakpoint: a software `break` cannot be written to the kernel's
        # high-half virtual address before the MMU is enabled at early boot (e.g.
        # start_kernel) — validated live during the Plan 3 PoC.
        args += ["-ex", f"hbreak {breakpoint}", "-ex", "continue"]
    return args
