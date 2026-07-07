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
    _write(tmp_path / "configs" / "default.toml", '[source]\nkind = "mmp"\nvalue = "6.6.30"\n')
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
