from pathlib import Path

from likedbg.config import load_config
from likedbg.debug_profiles import load_profiles
from likedbg.debug_profiles import resolve_run
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes

REPO = Path(__file__).resolve().parents[1]


def _host():
    p = Probes(
        system=lambda: "linux",
        machine=lambda: "x86_64",
        kvm_accessible=lambda: False,
        hvf_supported=lambda: False,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )
    return HostProfile.detect(load_config(REPO).settings, REPO, p)


def test_registry_loads_and_names_match() -> None:
    reg = load_profiles(REPO)
    assert {"exploit-dev", "hardened", "crash-debug", "kasan", "ubsan", "lockdep", "kcov-lite"} <= set(reg)
    assert reg["exploit-dev"].kind == "base" and reg["hardened"].kind == "base"


def test_default_run_resolves_exploit_dev_with_existing_fragments() -> None:
    cfg = load_config(REPO)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(), workspace=REPO)
    assert rr.profiles.base == "exploit-dev"
    for frag in rr.fragments:
        assert (REPO / frag).is_file()


def test_kasan_resolution_orders_and_implies() -> None:
    cfg = load_config(REPO)
    rr = resolve_run(profile_names=("kasan",), config=cfg, host=_host(), workspace=REPO)
    assert rr.profiles.names[:2] == ("exploit-dev", "crash-debug")
    assert "kasan" in rr.profiles.names
