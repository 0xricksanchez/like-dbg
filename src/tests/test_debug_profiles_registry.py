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
    assert parse_profile_names(["exploit-dev"]) == ("exploit-dev",)
    with pytest.raises(ConfigError):
        parse_profile_names("")
    with pytest.raises(ConfigError):
        parse_profile_names("KASAN")  # uppercase rejected, not normalized
