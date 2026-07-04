from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv


def _host(arch="arm64"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=arch,
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


def _argv(**kw):
    d = DebuggeeCfg(**{k: v for k, v in kw.items() if k in DebuggeeCfg.model_fields})
    return build_qemu_argv(
        d,
        _host(),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        share_host_dir=kw.get("share_host_dir"),
    )


def test_net_and_9p_present_by_default():
    s = " ".join(_argv(ssh_port=2222, share_host_dir=Path("/w/exploit")))
    assert "-netdev user,id=net0,hostfwd=tcp::2222-:22" in s
    assert "virtio-net-pci,netdev=net0" in s
    assert "-virtfs local,path=/w/exploit,mount_tag=exploit,security_model=mapped-xattr,id=fsdev0" in s


def test_toggles_off():
    s = " ".join(_argv(guest_net=False, share=False, share_host_dir=Path("/w/exploit")))
    assert "-netdev" not in s and "virtio-net-pci" not in s
    assert "-virtfs" not in s
