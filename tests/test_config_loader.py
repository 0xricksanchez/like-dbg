from pathlib import Path

import pytest

from likedbg.config import LAYER_CLI
from likedbg.config import LAYER_DEFAULT
from likedbg.config import LAYER_LOCAL
from likedbg.config import LAYER_PROFILE
from likedbg.config import LAYER_SCENARIO
from likedbg.config import load_config
from likedbg.errors import ConfigError


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_default_only(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[source]\nkind = "version"\nvalue = "6.6.30"\n')
    cr = load_config(tmp_path)
    assert cr.settings.source.value == "6.6.30"
    assert cr.provenance[("source", "value")] == LAYER_DEFAULT


def test_local_overrides_default_with_provenance(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[debugger]\next = "pwndbg"\n')
    _write(tmp_path / "configs" / "local.toml", '[debugger]\next = "gef"\n')
    cr = load_config(tmp_path)
    assert cr.settings.debugger.ext == "gef"
    assert cr.provenance[("debugger", "ext")] == LAYER_LOCAL


def test_missing_default_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_effective_debuggee_injects_profile_layer4(tmp_path: Path) -> None:
    # default.toml has kaslr off; a profile default flips it on; no user override → profile wins.
    _write(tmp_path / "configs" / "default.toml", "[debuggee]\nkaslr = false\n")
    cr = load_config(tmp_path)
    eff, prov = cr.effective_debuggee({"kaslr": "true"})
    assert eff.kaslr is True
    assert prov[("debuggee", "kaslr")] == LAYER_PROFILE


def test_effective_debuggee_user_beats_profile(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", "[debuggee]\nkaslr = false\n")
    _write(tmp_path / "configs" / "local.toml", "[debuggee]\nkaslr = false\n")
    cr = load_config(tmp_path)
    eff, prov = cr.effective_debuggee({"kaslr": "true"})
    assert eff.kaslr is False
    assert prov[("debuggee", "kaslr")] == LAYER_LOCAL


def test_cli_override_and_scenario(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[general]\narch = "native"\n')
    _write(tmp_path / "configs" / "scenarios" / "lk01.toml", '[general]\narch = "x86_64"\n')
    cr = load_config(
        tmp_path,
        scenario=tmp_path / "configs" / "scenarios" / "lk01.toml",
        cli_overrides={"debugger": {"ext": "gef"}},
    )
    assert cr.settings.general.arch == "x86_64"
    assert cr.settings.debugger.ext == "gef"
    assert cr.provenance[("general", "arch")] == LAYER_SCENARIO
    assert cr.provenance[("debugger", "ext")] == LAYER_CLI


def test_foreign_section_loads_through_scenario(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[general]\narch = "native"\n')
    _write(
        tmp_path / "configs" / "scenarios" / "lk01.toml",
        '[foreign]\nimage = "ctf/lk01/bzImage"\ncmdline = "quiet"\n',
    )
    cr = load_config(tmp_path, scenario=tmp_path / "configs" / "scenarios" / "lk01.toml")
    assert cr.settings.foreign.image == "ctf/lk01/bzImage"
    assert cr.settings.foreign.cmdline == "quiet"


def test_unknown_key_error_names_the_offending_key(tmp_path: Path) -> None:
    """A key that moved between releases (or a plain typo) must be identifiable from the error.
    'Extra inputs are not permitted' alone turns a one-line fix into a hunt through the section."""
    _write(tmp_path / "configs" / "default.toml", '[debugger]\next = "pwndbg"\nprofiles = ["exploit-dev"]\n')
    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path)
    assert "profiles" in str(exc.value)
    assert "[debugger]" in str(exc.value)
    assert exc.value.remedy and "profiles" in exc.value.remedy


def test_bad_value_error_names_the_offending_key(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[source]\nkind = "mmp"\n')
    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path)
    assert "kind" in str(exc.value)


def test_malformed_toml_is_a_config_error_not_a_traceback(tmp_path: Path) -> None:
    """Regression: a semantically wrong config got a ConfigError naming the key, but a
    syntactically wrong one escaped as tomllib.TOMLDecodeError. Fumbling a bracket while
    hand-editing a scenario is an everyday event."""
    _write(tmp_path / "configs" / "default.toml", '[foreign\nimage = "x"\n')
    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path)
    assert "invalid TOML" in str(exc.value)
    assert "line 1" in str(exc.value)  # tomllib's position is passed through, not paraphrased
    assert exc.value.remedy


def test_malformed_profile_toml_is_a_config_error(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[source]\nkind = "version"\nvalue = "6.6.30"\n')
    _write(tmp_path / "configs" / "profiles" / "broken.toml", 'name = "broken"\nkind = ["base"\n')
    from likedbg.debug_profiles import load_profiles

    with pytest.raises(ConfigError) as exc:
        load_profiles(tmp_path)
    assert "invalid TOML" in str(exc.value)
