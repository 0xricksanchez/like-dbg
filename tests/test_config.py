from pathlib import Path

import pytest
from pydantic import ValidationError

from likedbg.config import load_settings
from likedbg.errors import ConfigError

FIX = Path(__file__).parent / "fixtures"


def _load(**kw):
    return load_settings(FIX / "system.ini", FIX / "user.ini", **kw)


def test_user_overrides_system():
    s = _load()
    assert s.general.arch == "arm64"  # user.ini overrides system.ini
    assert s.debuggee.smep is False  # user.ini override
    assert s.debuggee.smap is True  # untouched system.ini value


def test_yes_no_become_bools():
    s = _load()
    assert s.debuggee.gdb is True
    assert s.kernel_builder.rust is False
    assert isinstance(s.debuggee.memory, int)


def test_blank_values_use_defaults_not_empty_string():
    s = _load()
    assert s.general.workspace_dir is None
    assert s.kernel_dl.tag is None


def test_cli_overrides_win_over_files():
    s = _load(overrides={"general": {"arch": "x86_64"}})
    assert s.general.arch == "x86_64"


def test_invalid_arch_raises_configerror():
    with pytest.raises(ConfigError):
        _load(overrides={"general": {"arch": "sparc"}})


def test_settings_is_immutable():
    s = _load()
    with pytest.raises(ValidationError):
        s.general.arch = "x86_64"  # type: ignore[misc]


def test_custom_ini_overrides_user(tmp_path):
    custom = tmp_path / "custom.ini"
    custom.write_text("[general]\narch = x86_64\n")
    s = _load(custom_ini=custom)
    assert s.general.arch == "x86_64"  # custom beats user.ini's arm64
