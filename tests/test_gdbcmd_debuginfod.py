from pathlib import Path

from likedbg.gdbcmd import build_gdb_args
from likedbg.gdbcmd import resolve_debuginfod_enabled
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


def test_resolve_debuginfod_enabled():
    assert resolve_debuginfod_enabled("on", is_foreign=False) is True
    assert resolve_debuginfod_enabled("on", is_foreign=True) is True
    assert resolve_debuginfod_enabled("off", is_foreign=False) is False
    assert resolve_debuginfod_enabled("off", is_foreign=True) is False
    assert resolve_debuginfod_enabled("auto", is_foreign=True) is True
    assert resolve_debuginfod_enabled("auto", is_foreign=False) is False


def _args(**kw):
    return build_gdb_args(
        _host(),
        arch="x86_64",
        vmlinux=Path("/w/vmlinux"),
        ext="pwndbg",
        breakpoint="start_kernel",
        **kw,
    )


def test_debuginfod_iex_emitted_when_enabled():
    args = _args(debuginfod_enabled=True, debuginfod_urls="https://debuginfod.elfutils.org")
    assert "set debuginfod enabled on" in args
    assert "set debuginfod urls https://debuginfod.elfutils.org" in args
    # never `ask` (would block a non-interactive session)
    assert not any("debuginfod enabled ask" in a for a in args)
    # both debuginfod -iex must come BEFORE the vmlinux load, like the extension/auto-load iex
    enable_idx = args.index("set debuginfod enabled on")
    vmlinux_idx = args.index("/w/vmlinux")
    assert enable_idx < vmlinux_idx


def test_debuginfod_absent_when_disabled():
    args = _args(debuginfod_enabled=False, debuginfod_urls="https://debuginfod.elfutils.org")
    assert not any("debuginfod" in a for a in args)


def test_debuginfod_urls_omitted_when_empty():
    args = _args(debuginfod_enabled=True, debuginfod_urls="")
    assert "set debuginfod enabled on" in args
    assert not any(a.startswith("set debuginfod urls") for a in args)
