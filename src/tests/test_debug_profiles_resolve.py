# src/tests/test_debug_profiles_resolve.py
from pathlib import Path

import pytest

from likedbg.config import GeneralCfg, Settings, load_config
from likedbg.debug_profiles import resolve_run
from likedbg.errors import ConfigError
from likedbg.host_profile import HostProfile, Probes


def _probes(machine="x86_64", system="linux"):
    return Probes(system=lambda: system, machine=lambda: machine, kvm_accessible=lambda: False,
                  hvf_supported=lambda: False, native_qemu_present=lambda _a: True,
                  workspace_case_sensitive=lambda _p: True)


def _scaffold(tmp_path: Path, *, kaslr_line: str = "kaslr = false") -> None:
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.toml").write_text(
        f'[source]\nkind="mmp"\nvalue="6.6.30"\n[debuggee]\n{kaslr_line}\n')
    pdir = tmp_path / "configs" / "profiles"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
        'fragments=["configs/fragments/generic.config","configs/fragments/no-kaslr.config"]\n'
        '[[expect]]\nsymbol="CONFIG_RANDOMIZE_BASE"\nvalue="n"\nseverity="hard"\n')
    (pdir / "crash-debug.toml").write_text(
        'name="crash-debug"\nkind="addon"\ndescription="d"\nfragments=["configs/fragments/profiles/crash-debug.config"]\n')
    (pdir / "kasan.toml").write_text(
        'name="kasan"\nkind="addon"\ndescription="d"\nimplies=["crash-debug"]\n'
        'fragments=["configs/fragments/profiles/kasan.config"]\n'
        '[[expect]]\nsymbol="CONFIG_KASAN"\nvalue="y"\nseverity="hard"\n')


def _host(tmp_path):
    return HostProfile.detect(Settings(general=GeneralCfg(arch="native")), tmp_path, _probes())


def test_kasan_implies_crash_debug_and_orders_fragments(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("kasan",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.profiles.names == ("exploit-dev", "crash-debug", "kasan")
    assert rr.profiles.base == "exploit-dev"
    # base fragments first, then implied add-on, then the explicit add-on
    assert rr.fragments == (
        "configs/fragments/generic.config",
        "configs/fragments/no-kaslr.config",
        "configs/fragments/profiles/crash-debug.config",
        "configs/fragments/profiles/kasan.config",
    )
    assert rr.implied_by["crash-debug"] == ("kasan",)


def test_unknown_profile_errors(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("asan",), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_explicit_kaslr_on_with_exploit_dev_is_contradiction(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    # user explicitly turns kaslr on via local.toml → explicit provenance
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nkaslr = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_default_kaslr_off_is_fine(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.kaslr is False
