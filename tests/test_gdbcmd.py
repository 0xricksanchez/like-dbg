from pathlib import Path

import pytest

from likedbg.gdbcmd import build_gdb_args
from likedbg.host_profile import HostProfile


def _host(addr="host.docker.internal"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr=addr,
        ssh_addr=addr,
    )


def _helper_arg(args):
    return next(arg for arg in args if "likedbg-reconnect" in arg)


def test_pwndbg_uses_target_remote_with_addr():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    s = " ".join(args)
    assert "target remote host.docker.internal:1234" in s
    assert "/w/vmlinux" in s
    # early-boot breakpoints must be hardware breakpoints (validated live)
    assert "hbreak start_kernel" in s
    # auto-load must be enabled before the symbol file loads
    assert "set auto-load safe-path /" in s


def test_safe_path_is_an_initial_command_before_the_file():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert args.index("-iex") < args.index("/w/vmlinux")


def test_gef_uses_gef_remote_not_qemu_user():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "gef-remote host.docker.internal 1234" in s
    assert "--qemu-user" not in s


def test_no_breakpoint_omits_break():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert "hbreak start_kernel" not in args
    assert "continue" not in args
    helper = _helper_arg(args)
    assert "breakpoint = None" in helper


def test_gef_sources_only_the_gef_plugin():
    # Both gef and pwndbg are installed in the image; the requested ext is sourced
    # explicitly (~/.gdbinit no longer auto-loads one) and the other must not appear.
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "source /opt/gef/gef.py" in s
    assert "/opt/pwndbg" not in s


def test_pwndbg_sources_only_the_pwndbg_plugin():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    s = " ".join(args)
    assert "source /opt/pwndbg/gdbinit.py" in s
    assert "/opt/gef" not in s


def test_extension_is_sourced_before_the_symbol_file():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert args.index("source /opt/gef/gef.py") < args.index("/w/vmlinux")


def test_sets_x86_64_gdb_architecture():
    args = build_gdb_args(_host(), arch="x86_64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert "set architecture i386:x86-64" in " ".join(args)


def test_sets_arm64_gdb_architecture():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert "set architecture aarch64" in " ".join(args)


def test_unknown_arch_raises_clear_error():
    with pytest.raises(ValueError, match="unsupported gdb architecture"):
        build_gdb_args(_host(), arch="riscv64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)


def test_remote_port_is_configurable():
    gef = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None, port=4444)
    assert "gef-remote host.docker.internal 4444" in " ".join(gef)
    pdb = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None, port=4444)
    assert "target remote host.docker.internal:4444" in " ".join(pdb)


def test_gef_reconnect_helper_disconnects_before_gef_remote():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert "likedbg-reconnect" in helper
    assert "disconnect" in helper
    assert "except gdb.error" in helper
    assert helper.index("disconnect") < helper.index("gef-remote host.docker.internal 1234")


def test_pwndbg_reconnect_helper_disconnects_before_target_remote():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert "likedbg-reconnect" in helper
    assert "disconnect" in helper
    assert "except gdb.error" in helper
    assert helper.index("disconnect") < helper.index("target remote host.docker.internal:1234")


def test_reconnect_helper_reapplies_initial_breakpoint_and_continues():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert '_set_pwndbg_context_sections("")' in helper
    assert "pwndbg.config.context_sections.value = value" in helper
    assert "set context-sections" in helper
    assert 'getattr(bp, "enabled", True)' in helper
    assert "if not _breakpoint_exists(breakpoint)" in helper
    assert 'hbreak " + breakpoint' in helper
    assert 'gdb.execute("continue", from_tty=from_tty)' in helper
    assert "hbreak start_kernel" in args
    assert "continue" in args
