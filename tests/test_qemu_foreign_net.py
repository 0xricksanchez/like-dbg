import pytest

from likedbg.foreign import ForeignError
from likedbg.qemu import _foreign_nic_args


def test_ethN_injects_net_ifnames_and_auto_slot():
    device, tokens = _foreign_nic_args("eth0", "console=ttyS0 loglevel=3")
    assert device == "virtio-net-pci,netdev=net0"
    assert tokens == ["net.ifnames=0"]


def test_ethN_does_not_duplicate_existing_net_ifnames():
    device, tokens = _foreign_nic_args("eth0", "console=ttyS0 net.ifnames=0")
    assert tokens == []


def test_enp0sN_pins_pci_slot_no_net_ifnames():
    device, tokens = _foreign_nic_args("enp0s3", "console=ttyS0")
    assert device == "virtio-net-pci,netdev=net0,addr=0x3"
    assert tokens == []


def test_enp0sN_two_digit_slot_converts_to_hex():
    device, tokens = _foreign_nic_args("enp0s16", "console=ttyS0")
    assert device == "virtio-net-pci,netdev=net0,addr=0x10"  # 16 decimal -> 0x10, NOT 0x16
    assert tokens == []


def test_enp0sN_conflicts_with_net_ifnames_0():
    with pytest.raises(ForeignError):
        _foreign_nic_args("enp0s3", "console=ttyS0 net.ifnames=0")


def test_unsupported_scheme_raises():
    with pytest.raises(ForeignError):
        _foreign_nic_args("ens3", "console=ttyS0")
