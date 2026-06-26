from pathlib import Path

import pytest

from likedbg.debug_profiles import load_profiles, parse_profile_names
from likedbg.errors import ConfigError


def _profile(dirp: Path, name: str, body: str) -> None:
    dirp.mkdir(parents=True, exist_ok=True)
    (dirp / f"{name}.toml").write_text(body)


def test_load_minimal_addon(tmp_path: Path) -> None:
    pdir = tmp_path / "configs" / "profiles"
    _profile(pdir, "kasan", 'name = "kasan"\nkind = "addon"\ndescription = "x"\nimplies = ["crash-debug"]\n'
             'fragments = ["configs/fragments/profiles/kasan.config"]\n'
             '[[expect]]\nsymbol = "CONFIG_KASAN"\nvalue = "y"\nseverity = "hard"\n')
    reg = load_profiles(tmp_path)
    assert reg["kasan"].kind == "addon"
    assert reg["kasan"].implies == ("crash-debug",)
    assert reg["kasan"].expect[0].symbol == "CONFIG_KASAN"


def test_filename_must_match_name(tmp_path: Path) -> None:
    _profile(tmp_path / "configs" / "profiles", "kasan", 'name = "ubsan"\nkind = "addon"\ndescription = "x"\n')
    with pytest.raises(ConfigError):
        load_profiles(tmp_path)


def test_unknown_field_rejected(tmp_path: Path) -> None:
    _profile(tmp_path / "configs" / "profiles", "x", 'name = "x"\nkind = "addon"\ndescription = "d"\nbogus = 1\n')
    with pytest.raises(ConfigError):
        load_profiles(tmp_path)


def test_parse_profile_names() -> None:
    assert parse_profile_names("kasan,lockdep") == ("kasan", "lockdep")
    assert parse_profile_names("kasan,kasan,lockdep") == ("kasan", "lockdep")
    assert parse_profile_names(["exploit-dev"]) == ("exploit-dev",)
    with pytest.raises(ConfigError):
        parse_profile_names("")
    with pytest.raises(ConfigError):
        parse_profile_names("KASAN")  # uppercase rejected, not normalized

# ---------------------------------------------------------------------------
# FIX 2: path-traversal validation for profile fragments
# ---------------------------------------------------------------------------


def test_profile_fragment_absolute_path_rejected(tmp_path: Path) -> None:
    """A profile with an absolute fragment path must raise ConfigError."""
    pdir = tmp_path / "configs" / "profiles"
    _profile(pdir, "bad", 'name = "bad"\nkind = "addon"\ndescription = "d"\nfragments = ["/etc/bad.config"]\n')
    with pytest.raises(ConfigError, match="absolute"):
        load_profiles(tmp_path)


def test_profile_fragment_dotdot_rejected(tmp_path: Path) -> None:
    """A profile with '..' in a fragment path must raise ConfigError."""
    pdir = tmp_path / "configs" / "profiles"
    _profile(
        pdir,
        "bad",
        'name = "bad"\nkind = "addon"\ndescription = "d"\nfragments = ["configs/fragments/../../evil.config"]\n',
    )
    with pytest.raises(ConfigError, match="traversal"):
        load_profiles(tmp_path)


def test_profile_fragment_outside_configs_fragments_rejected(tmp_path: Path) -> None:
    """A profile fragment not under configs/fragments/ must raise ConfigError."""
    pdir = tmp_path / "configs" / "profiles"
    _profile(
        pdir,
        "bad",
        'name = "bad"\nkind = "addon"\ndescription = "d"\nfragments = ["my-workspace/bad.config"]\n',
    )
    with pytest.raises(ConfigError, match="configs/fragments/"):
        load_profiles(tmp_path)


def test_profile_fragment_valid_path_accepted(tmp_path: Path) -> None:
    """A valid configs/fragments/ path is accepted without error."""
    pdir = tmp_path / "configs" / "profiles"
    _profile(
        pdir,
        "good",
        'name = "good"\nkind = "addon"\ndescription = "d"\nfragments = ["configs/fragments/profiles/good.config"]\n',
    )
    reg = load_profiles(tmp_path)
    assert reg["good"].fragments == ("configs/fragments/profiles/good.config",)
