import pytest
from pydantic import ValidationError

from likedbg.config import BuildCfg, DebuggerCfg, DebuggingCfg, GeneralCfg, Settings, SourceCfg


def test_defaults_match_grill_decisions() -> None:
    s = Settings()
    assert s.general.arch == "native"
    assert s.source.kind == "mmp"
    assert s.debugger.ext == "pwndbg"  # de facto default (Q9)
    assert s.debugging.profiles == ("exploit-dev",)


def test_list_fields_are_tuples() -> None:
    b = BuildCfg(patch_dirs=["patches/uaf"], extra_fragments=["configs/fragments/local/x.config"])
    assert b.patch_dirs == ("patches/uaf",)
    assert b.extra_fragments == ("configs/fragments/local/x.config",)
    assert DebuggingCfg(profiles=["kasan", "lockdep"]).profiles == ("kasan", "lockdep")


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneralCfg(arch="native", bogus=1)  # type: ignore[call-arg]


def test_source_kind_constrained() -> None:
    with pytest.raises(ValidationError):
        SourceCfg(kind="branch", value="x")  # type: ignore[arg-type]
