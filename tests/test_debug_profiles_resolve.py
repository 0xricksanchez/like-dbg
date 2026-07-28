# src/tests/test_debug_profiles_resolve.py
from pathlib import Path

import pytest

from likedbg.config import GeneralCfg
from likedbg.config import Settings
from likedbg.config import load_config
from likedbg.debug_profiles import resolve_run
from likedbg.errors import ConfigError
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes


def _probes(machine="x86_64", system="linux"):
    return Probes(
        system=lambda: system,
        machine=lambda: machine,
        kvm_accessible=lambda: False,
        hvf_supported=lambda: False,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )


def _scaffold(tmp_path: Path, *, kaslr_line: str = "kaslr = false") -> None:
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.toml").write_text(
        f'[source]\nkind="version"\nvalue="6.6.30"\n[debuggee]\n{kaslr_line}\n'
    )
    pdir = tmp_path / "configs" / "profiles"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
        'fragments=["configs/fragments/generic.config","configs/fragments/no-kaslr.config"]\n'
        '[[expect]]\nsymbol="CONFIG_RANDOMIZE_BASE"\nvalue="n"\nseverity="hard"\n'
    )
    (pdir / "crash-debug.toml").write_text(
        'name="crash-debug"\nkind="addon"\ndescription="d"\nfragments=["configs/fragments/profiles/crash-debug.config"]\n'
    )
    (pdir / "kasan.toml").write_text(
        'name="kasan"\nkind="addon"\ndescription="d"\nimplies=["crash-debug"]\n'
        'fragments=["configs/fragments/profiles/kasan.config"]\n'
        '[[expect]]\nsymbol="CONFIG_KASAN"\nvalue="y"\nseverity="hard"\n'
    )


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


def test_foreign_run_does_not_apply_native_profile_build_gate(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nkaslr = true\n")
    cfg = load_config(tmp_path)
    rr = resolve_run(
        profile_names=("exploit-dev",),
        config=cfg,
        host=_host(tmp_path),
        workspace=tmp_path,
        validate_build_gates=False,
    )
    assert rr.effective_debuggee.kaslr is True


def test_default_kaslr_off_is_fine(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.kaslr is False


def test_implies_unknown_profile_errors(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    pdir = tmp_path / "configs" / "profiles"
    (pdir / "broken.toml").write_text('name="broken"\nkind="addon"\ndescription="d"\nimplies=["nonexistent"]\n')
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("broken",), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_two_base_profiles_is_exclusivity_error(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    pdir = tmp_path / "configs" / "profiles"
    (pdir / "hardened.toml").write_text('name="hardened"\nkind="base"\ndescription="d"\n')
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("exploit-dev", "hardened"), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def _host_arm64(tmp_path):
    return HostProfile.detect(Settings(general=GeneralCfg(arch="arm64")), tmp_path, _probes(machine="arm64"))


def _write_profile(tmp_path: Path, name: str, expect_symbol: str) -> None:
    (tmp_path / "configs" / "profiles" / f"{name}.toml").write_text(
        f'name="{name}"\nkind="addon"\ndescription="d"\n'
        f'fragments=["configs/fragments/profiles/{name}.config"]\n'
        f'[[expect]]\nsymbol="{expect_symbol}"\nvalue="n"\nseverity="hard"\n'
    )


def test_explicit_kpti_on_with_renamed_symbol_built_off_is_contradiction(tmp_path: Path) -> None:
    # kconfig gate exercises the 6.8+ symbol rename alias (CONFIG_MITIGATION_PAGE_TABLE_ISOLATION).
    _scaffold(tmp_path)
    _write_profile(tmp_path, "no-kpti", "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION")
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nkpti = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError, match="CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"):
        resolve_run(profile_names=("exploit-dev", "no-kpti"), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_explicit_smep_on_arm64_is_arch_error(tmp_path: Path) -> None:
    # arch gate: SMEP is an x86_64-only CPU feature, so an explicit smep=on for an arm64 target is impossible.
    _scaffold(tmp_path)
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nsmep = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError, match="x86_64-only"):
        resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host_arm64(tmp_path), workspace=tmp_path)


def test_explicit_smap_on_arm64_is_arch_error(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nsmap = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError, match="x86_64-only"):
        resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host_arm64(tmp_path), workspace=tmp_path)


def test_default_smep_smap_on_arm64_is_fine(tmp_path: Path) -> None:
    # smep/smap default on but are NOT explicit, so the arch gate must not fire (harmless no-op on arm64).
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host_arm64(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.smep is True
    assert rr.effective_debuggee.smap is True


def test_explicit_smep_smap_on_x86_is_fine(tmp_path: Path) -> None:
    # x86_64 target and no profile disables them, so an explicit smep/smap=on is allowed.
    _scaffold(tmp_path)
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nsmep = true\nsmap = true\n")
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.smep is True
    assert rr.effective_debuggee.smap is True


def test_explicit_fgkaslr_on_arm64_is_arch_error(tmp_path: Path) -> None:
    # FG-KASLR is x86_64-only, so an explicit fgkaslr=on for an arm64 target is impossible.
    _scaffold(tmp_path)
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nfgkaslr = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError, match="x86_64-only"):
        resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host_arm64(tmp_path), workspace=tmp_path)


def test_default_fgkaslr_on_arm64_is_fine(tmp_path: Path) -> None:
    # fgkaslr defaults on but is NOT explicit, so the arch gate must not fire on an arm64 target.
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host_arm64(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.fgkaslr is True
