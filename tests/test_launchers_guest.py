from pathlib import Path

from likedbg.launchers import qemu_container_command


def test_publishes_ssh_port_and_binds_share():
    cmd = qemu_container_command(
        ["qemu-system-x86_64"],
        image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")],
        rw_mounts=[Path("/w/rootfs.img")],
        gdbstub_port=1234,
        ssh_port=2222,
        network_mode="published",
        extra_rw_dirs=(Path("/w/exploit"),),
    )
    assert "-p 1234:1234" in cmd
    assert "-p 2222:2222" in cmd
    assert "-v /w/exploit:/w/exploit:rw" in cmd


def test_host_net_no_ssh_publish():
    cmd = qemu_container_command(
        ["qemu-system-x86_64"],
        image="img",
        ro_mounts=[],
        rw_mounts=[],
        ssh_port=2222,
        network_mode="host",
    )
    assert "-p 2222" not in cmd and "--network host" in cmd
