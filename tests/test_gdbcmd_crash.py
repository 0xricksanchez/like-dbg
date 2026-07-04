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


def test_crash_breakpoints_installed_after_reaching_start_kernel():
    # Software crash breakpoints must be CREATED while gdb is stopped at the
    # start_kernel hardware breakpoint (kernel VA space mapped), so their
    # insertion is deferred to the user's next `continue`. Creating them before
    # the initial `continue` makes early-boot insertion fail (MMU off) and the
    # guest never boots. Lock the ordering to prevent regression.
    args = build_gdb_args(
        _host(),
        arch="x86_64",
        vmlinux=Path("/w/vmlinux"),
        ext="pwndbg",
        breakpoint="start_kernel",
        break_on_crash=True,
        crash_breakpoints=("panic", "die", "kasan_report"),
    )
    crash_idx = next(i for i, a in enumerate(args) if "crash.gdb.json" in a)
    hbreak_idx = args.index("hbreak start_kernel")
    continue_idx = len(args) - 1 - args[::-1].index("continue")
    assert crash_idx > hbreak_idx
    assert crash_idx > continue_idx


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
