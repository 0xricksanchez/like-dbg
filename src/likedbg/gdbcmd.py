"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

from pathlib import Path

from likedbg.host_profile import HostProfile


def build_gdb_args(host: HostProfile, *, vmlinux: Path, ext: str, breakpoint: str | None) -> list[str]:
    addr = host.gdbstub_addr
    # `-iex "set auto-load safe-path /"` runs BEFORE the symbol file loads, so the
    # kernel's vmlinux-gdb.py / lx- helpers auto-load cleanly (a later -ex is too late).
    args = ["gdb-multiarch", "-q", "-iex", "set auto-load safe-path /", str(vmlinux)]
    args += ["-ex", "set architecture aarch64"]
    if ext == "gef":
        args += ["-ex", f"gef-remote {addr} 1234"]
    else:
        args += ["-ex", f"target remote {addr}:1234"]
    if breakpoint is not None:
        # Hardware breakpoint: a software `break` cannot be written to the kernel's
        # high-half virtual address before the MMU is enabled at early boot (e.g.
        # start_kernel) — validated live during the Plan 3 PoC.
        args += ["-ex", f"hbreak {breakpoint}", "-ex", "continue"]
    return args
