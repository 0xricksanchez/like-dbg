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
        ["gdb-multiarch", "-q", "/ksrc/linux-6.6.30/vmlinux", "-ex", "hbreak start_kernel"],
        image="like_debugger:latest",
        kernel_volume="likedbg_ksrc",
    )
    assert cmd.startswith("docker run --rm")
    assert "--add-host=host.docker.internal:host-gateway" in cmd
    assert "-v likedbg_ksrc:/ksrc:ro" in cmd
    assert "like_debugger:latest" in cmd
    assert "hbreak start_kernel" in cmd
