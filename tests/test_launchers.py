from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_pane_command


def test_qemu_pane_command_joins_argv():
    cmd = qemu_pane_command(["qemu-system-aarch64", "-accel", "hvf", "-kernel", "/ws/Image"])
    assert cmd == "qemu-system-aarch64 -accel hvf -kernel /ws/Image"


def test_qemu_pane_command_quotes_multiword_append():
    # A multi-word -append value must stay a single shell token through tmux send-keys.
    cmd = qemu_pane_command(["qemu-system-aarch64", "-append", "console=ttyAMA0 nokaslr pti=on"])
    assert "'console=ttyAMA0 nokaslr pti=on'" in cmd


def test_gdb_pane_command_wraps_docker_run_with_addhost_and_volume():
    cmd = gdb_pane_command(
        ["gdb-multiarch", "-q", "/ksrc/x/vmlinux", "-ex", "hbreak start_kernel"],
        image="like_debugger:latest",
        mount_source="likedbg_ksrc",
    )
    assert cmd.startswith("docker run --rm")
    assert "--add-host=host.docker.internal:host-gateway" in cmd
    assert "-v likedbg_ksrc:/ksrc:ro" in cmd
    assert "like_debugger:latest" in cmd
    assert "hbreak start_kernel" in cmd


def test_gdb_pane_command_accepts_bind_dir_mount_source():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/ws/artifacts/builds/x")
    assert "-v /ws/artifacts/builds/x:/ksrc:ro" in cmd
