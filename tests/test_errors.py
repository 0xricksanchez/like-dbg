import pytest

from likedbg.errors import ConfigError
from likedbg.errors import HostCapabilityError
from likedbg.errors import LikeDbgError


def test_message_only():
    err = LikeDbgError("bad thing")
    assert err.message == "bad thing"
    assert err.remedy is None
    assert str(err) == "bad thing"


def test_message_with_remedy_renders_fix_line():
    err = HostCapabilityError("no qemu", remedy="run 'just bootstrap'")
    assert err.remedy == "run 'just bootstrap'"
    assert str(err) == "no qemu\n  -> fix: run 'just bootstrap'"


def test_subclasses_are_likedbgerror():
    assert issubclass(ConfigError, LikeDbgError)
    with pytest.raises(LikeDbgError):
        raise ConfigError("nope")
