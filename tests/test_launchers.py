from pathlib import Path

from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_container_command
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
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/ws/artifacts/ksrc/x")
    assert "-v /ws/artifacts/ksrc/x:/ksrc:ro" in cmd


def test_qemu_container_command_publishes_port_mounts_and_wraps_argv():
    cmd = qemu_container_command(
        ["qemu-system-x86_64", "-accel", "tcg", "-kernel", "/ws/artifacts/x/Image", "-S", "-s"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/ws/artifacts/x/Image")],
        rw_mounts=[Path("/ws/artifacts/rootfs/r.img")],
    )
    assert cmd.startswith("docker run --rm -it -p 1234:1234")
    assert "-v /ws/artifacts/x/Image:/ws/artifacts/x/Image:ro" in cmd  # kernel read-only
    assert "-v /ws/artifacts/rootfs/r.img:/ws/artifacts/rootfs/r.img:rw" in cmd  # rootfs disk writable
    assert "like_debuggee:latest" in cmd
    assert cmd.rstrip().endswith("-S -s")  # argv appended last


def test_qemu_container_command_omits_absent_rootfs():
    cmd = qemu_container_command(
        ["qemu-system-x86_64", "-kernel", "/ws/Image"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/ws/Image")],
        rw_mounts=[],
    )
    assert "-v /ws/Image:/ws/Image:ro" in cmd
    assert ":rw" not in cmd  # no writable mount when there's no rootfs disk


def test_qemu_container_host_network_omits_published_port():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")],
        rw_mounts=[],
        network_mode="host",
    )
    assert "--network host" in cmd
    assert "-p 1234:1234" not in cmd  # host net and -p are mutually exclusive


def test_qemu_container_kvm_passes_device():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")],
        rw_mounts=[],
        network_mode="host",
        kvm=True,
    )
    assert "--device /dev/kvm" in cmd


def test_qemu_container_no_kvm_omits_device():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")],
        rw_mounts=[],
    )
    assert "/dev/kvm" not in cmd


def test_gdb_pane_host_network_uses_localhost_path_not_gateway():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/ws/artifacts/ksrc", network_mode="host")
    assert "--network host" in cmd
    assert "--add-host=host.docker.internal:host-gateway" not in cmd
    assert "-v /ws/artifacts/ksrc:/ksrc:ro" in cmd
