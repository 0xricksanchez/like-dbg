from ..kernel_builder import KernelBuilder
from pathlib import Path
import collections
import configparser
from unittest.mock import patch
import os


USER_INI = Path("configs/user.ini")


def fetch_cfg_value_from_section_and_key(sect: str, key: str) -> str:
    cfg = configparser.ConfigParser()
    cfg.read(USER_INI)
    try:
        return cfg[sect][key]
    except KeyError:
        return ""


def test_make_sudo_fail() -> None:
    assert KernelBuilder.make_sudo("test") == "test"


@patch("os.getuid", return_value=42)
def test_make_sudo_success(self) -> None:
    assert os.getuid() == 42
    # kb = KernelBuilder(**{"kroot": "foo"})
    # assert kb.make_sudo("test") == "sudo test"


def test_custom_args() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.enable_args = "FOO BAR"
    kb.disable_args = " BAZ QUX"
    assert kb._custom_args() == "-e FOO -e BAR -d BAZ -d QUX"


def test_extra_args() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.extra_args = "-e FOO -d BAR"
    expected = "-e FOO -d BAR".split()
    actual = kb._extra_args("-e BAR").split()
    compare = lambda x, y: collections.Counter(x) == collections.Counter(y)
    assert compare(expected, actual) == True


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_syzkaller(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "syzkaller"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key("kernel_builder", "syzkaller_args")


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_generic(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "generic"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key("kernel_builder", "generic_args")


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_custom(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "custom"
    kb.enable_args = "FOO BAR"
    kb.disable_args = " BAZ QUX"
    assert kb._get_params() == "-e FOO -e BAR -d BAZ -d QUX"


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_extra(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = ""
    kb.extra_args = "-e FOO -d BAR"
    assert kb._get_params() == kb.extra_args


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_extra_override(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "generic"
    kb.extra_args = "-d DEBUG_KERNEL"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key("kernel_builder", "generic_args").replace("-e DEBUG_KERNEL", kb.extra_args)
