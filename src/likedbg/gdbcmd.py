"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

from pathlib import Path

from likedbg.host_profile import HostProfile


def build_gdb_args(host: HostProfile, *, vmlinux: Path, ext: str, breakpoint: str | None) -> list[str]:
    addr = host.gdbstub_addr
    args = ["gdb-multiarch", "-q", str(vmlinux), "-ex", "set architecture aarch64"]
    if ext == "gef":
        args += ["-ex", f"gef-remote {addr} 1234"]
    else:
        args += ["-ex", f"target remote {addr}:1234"]
    args += ["-ex", "add-auto-load-safe-path /"]
    if breakpoint is not None:
        args += ["-ex", f"break {breakpoint}", "-ex", "continue"]
    return args
