from pathlib import Path

import pytest

from likedbg.config import Settings
from likedbg.errors import HostCapabilityError
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes


def _settings(arch="arm64", accel="auto", mac_storage="auto"):
    return Settings.model_validate(
        {"general": {"arch": arch, "mac_storage": mac_storage}, "debuggee": {"accel": accel}}
    )


def _probes(*, system, machine, kvm=False, hvf=False, qemu=False, case_sensitive=True):
    return Probes(
        system=lambda: system,
        machine=lambda: machine,
        kvm_accessible=lambda: kvm,
        hvf_supported=lambda: hvf,
        native_qemu_present=lambda arch: qemu,
        workspace_case_sensitive=lambda path: case_sensitive,
    )


def test_arm64_on_arm_mac_uses_native_hvf():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("hvf", "native-host")
    assert hp.gdbstub_addr == "host.docker.internal"


def test_x86_on_arm_mac_stays_in_container_tcg():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=False)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("tcg", "in-container")


def test_linux_same_arch_with_kvm():
    p = _probes(system="linux", machine="x86_64", kvm=True)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("kvm", "in-container")
    assert hp.gdbstub_addr == "localhost"


def test_auto_degrades_to_tcg_when_no_accel():
    p = _probes(system="darwin", machine="arm64", hvf=False, qemu=False)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.accel == "tcg"
    assert hp.debuggee_mode == "in-container"


def test_explicit_unsatisfiable_accel_raises():
    p = _probes(system="linux", machine="x86_64", kvm=False)
    with pytest.raises(HostCapabilityError):
        HostProfile.detect(_settings("x86_64", accel="kvm"), Path("/ws"), p)


def test_storage_volume_on_case_insensitive_mac():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True, case_sensitive=False)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.storage_mode == "volume"


def test_storage_bind_on_linux_always():
    p = _probes(system="linux", machine="x86_64", kvm=True, case_sensitive=False)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert hp.storage_mode == "bind"


def test_explicit_hvf_unsatisfiable_raises():
    p = _probes(system="darwin", machine="arm64", hvf=False, qemu=False)
    with pytest.raises(HostCapabilityError):
        HostProfile.detect(_settings("arm64", accel="hvf"), Path("/ws"), p)


def test_explicit_mac_storage_override_wins_over_detection():
    # case-sensitive workspace, but override forces volume
    p_vol = _probes(system="darwin", machine="arm64", hvf=True, qemu=True, case_sensitive=True)
    hp_vol = HostProfile.detect(_settings("arm64", mac_storage="volume"), Path("/ws"), p_vol)
    assert hp_vol.storage_mode == "volume"
    # case-insensitive workspace, but override forces bind
    p_bind = _probes(system="darwin", machine="arm64", hvf=True, qemu=True, case_sensitive=False)
    hp_bind = HostProfile.detect(_settings("arm64", mac_storage="bind"), Path("/ws"), p_bind)
    assert hp_bind.storage_mode == "bind"
