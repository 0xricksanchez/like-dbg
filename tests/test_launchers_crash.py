from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_container_command


def test_qemu_container_mounts_extra_rw_dir():
    cmd = qemu_container_command(
        ["qemu-system-x86_64"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")],
        rw_mounts=[Path("/w/rootfs.img")],
        extra_rw_dirs=(Path("/w/artifacts/runs/r1/logs"),),
    )
    assert "-v /w/artifacts/runs/r1/logs:/w/artifacts/runs/r1/logs:rw" in cmd


def test_gdb_pane_command_adds_crash_drop_mount():
    cmd = gdb_pane_command(
        ["gdb-multiarch"],
        image="like_debugger:latest",
        mount_source="/w/ksrc",
        crash_drop=Path("/w/runs/r1/crash"),
    )
    assert f"-v /w/runs/r1/crash:{CRASH_DROP_MOUNT}:rw" in cmd


def test_gdb_pane_command_no_crash_drop_by_default():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/w/ksrc")
    assert CRASH_DROP_MOUNT not in cmd
