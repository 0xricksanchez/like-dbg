from pathlib import Path

import pytest

from likedbg.config import DebuggeeCfg
from likedbg.foreign import ForeignError
from likedbg.host_profile import HostProfile
from likedbg.qemu import _foreign_nic_args
from likedbg.qemu import build_qemu_argv


def test_ethn_injects_net_ifnames_and_auto_slot():
    device, tokens = _foreign_nic_args("eth0", "console=ttyS0 loglevel=3")
    assert device == "virtio-net-pci,netdev=net0"
    assert tokens == ["net.ifnames=0"]


def test_ethn_does_not_duplicate_existing_net_ifnames():
    device, tokens = _foreign_nic_args("eth0", "console=ttyS0 net.ifnames=0")
    assert tokens == []


def test_ethn_conflicting_net_ifnames_raises():
    # symmetry with enp0sN: an ethN request against a cmdline that forces predictable naming is a
    # contradiction, not a silent degrade (the NIC would never come up as ethN -> the ifup wait stalls).
    with pytest.raises(ForeignError):
        _foreign_nic_args("eth0", "console=ttyS0 net.ifnames=1")


def test_enp0sn_pins_pci_slot_no_net_ifnames():
    device, tokens = _foreign_nic_args("enp0s3", "console=ttyS0")
    assert device == "virtio-net-pci,netdev=net0,addr=0x3"
    assert tokens == []


def test_enp0sn_two_digit_slot_converts_to_hex():
    device, tokens = _foreign_nic_args("enp0s16", "console=ttyS0")
    assert device == "virtio-net-pci,netdev=net0,addr=0x10"  # 16 decimal -> 0x10, NOT 0x16
    assert tokens == []


def test_enp0sn_conflicts_with_net_ifnames_0():
    with pytest.raises(ForeignError):
        _foreign_nic_args("enp0s3", "console=ttyS0 net.ifnames=0")


def test_unsupported_scheme_raises():
    with pytest.raises(ForeignError):
        _foreign_nic_args("ens3", "console=ttyS0")


def _foreign_argv(*, net=True, net_iface="eth0", cmdline="console=ttyS0 loglevel=3"):
    host = HostProfile(
        os="linux",
        host_arch="x86_64",
        target_arch="x86_64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="localhost",
    )
    d = DebuggeeCfg(guest_net=False, share=False)  # foreign: control transport off
    return build_qemu_argv(
        d,
        host,
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline=cmdline,
        foreign_net=net,
        foreign_net_iface=net_iface,
    )


def test_foreign_eth0_emits_slirp_nic_no_hostfwd():
    s = " ".join(_foreign_argv(net_iface="eth0"))
    assert "-netdev user,id=net0" in s
    assert "hostfwd" not in s
    assert "-device virtio-net-pci,netdev=net0" in s
    assert "net.ifnames=0" in s


def test_foreign_enp0s3_pins_slot_and_omits_net_ifnames():
    s = " ".join(_foreign_argv(net_iface="enp0s3"))
    assert "virtio-net-pci,netdev=net0,addr=0x3" in s
    assert "net.ifnames=0" not in s


def test_foreign_net_off_emits_no_nic_and_verbatim_cmdline():
    s = " ".join(_foreign_argv(net=False))
    assert "-netdev" not in s and "virtio-net-pci" not in s
    assert "net.ifnames" not in s
