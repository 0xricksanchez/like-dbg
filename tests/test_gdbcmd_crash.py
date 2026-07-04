from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.gdbcmd import build_gdb_args
from likedbg.host_profile import HostProfile


def _host():
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="x86_64",
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )


def test_crash_breakpoints_injected_when_enabled():
    args = build_gdb_args(
        _host(),
        arch="x86_64",
        vmlinux=Path("/w/vmlinux"),
        ext="pwndbg",
        breakpoint="start_kernel",
        break_on_crash=True,
        crash_breakpoints=("panic", "die", "kasan_report"),
    )
    joined = "\n".join(args)
    assert "panic" in joined and "die" in joined and "kasan_report" in joined
    assert f"{CRASH_DROP_MOUNT}/crash.gdb.json" in joined
    assert "gdb.Breakpoint" in joined


def test_no_crash_breakpoints_when_disabled():
    args = build_gdb_args(
        _host(),
        arch="x86_64",
        vmlinux=Path("/w/vmlinux"),
        ext="pwndbg",
        breakpoint="start_kernel",
        break_on_crash=False,
        crash_breakpoints=("panic",),
    )
    assert "crash.gdb.json" not in "\n".join(args)
