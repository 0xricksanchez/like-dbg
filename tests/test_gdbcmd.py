from pathlib import Path

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


def test_pwndbg_uses_target_remote_with_addr():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    s = " ".join(args)
    assert "target remote host.docker.internal:1234" in s
    assert "/w/vmlinux" in s
    assert "break start_kernel" in s


def test_gef_uses_gef_remote_not_qemu_user():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "gef-remote host.docker.internal 1234" in s
    assert "--qemu-user" not in s


def test_no_breakpoint_omits_break():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert all("break" not in a for a in args)
