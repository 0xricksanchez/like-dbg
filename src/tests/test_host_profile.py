from pathlib import Path

from likedbg.config import Settings, GeneralCfg
from likedbg.host_profile import HostProfile, Probes


def _probes(*, system: str, machine: str) -> Probes:
    return Probes(
        system=lambda: system,
        machine=lambda: machine,
        kvm_accessible=lambda: False,
        hvf_supported=lambda: True,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )


def test_native_resolves_to_host_arch(tmp_path: Path) -> None:
    s = Settings(general=GeneralCfg(arch="native"))
    hp = HostProfile.detect(s, tmp_path, _probes(system="darwin", machine="arm64"))
    assert hp.target_arch == "arm64"
    assert hp.accel == "hvf" and hp.debuggee_mode == "native-host"  # same-arch path uses target_arch


def test_explicit_cross_arch_kept(tmp_path: Path) -> None:
    s = Settings(general=GeneralCfg(arch="x86_64"))
    hp = HostProfile.detect(s, tmp_path, _probes(system="darwin", machine="arm64"))
    assert hp.target_arch == "x86_64"
    assert hp.debuggee_mode == "in-container"  # cross-arch on mac → TCG in container
