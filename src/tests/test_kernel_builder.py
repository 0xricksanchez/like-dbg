from ..kernel_builder import KernelBuilder, MISC_DRVS_PATH
from pathlib import Path
import collections
import configparser
from unittest.mock import patch
import uuid


USER_INI = Path("configs/user.ini")
CUSTOM_MODULE = Path("examples/like_dbg_confs/echo_module.ini")


def fetch_cfg_value_from_section_and_key(c: Path, sect: str, key: str) -> str:
    cfg = configparser.ConfigParser()
    cfg.read(c)
    return cfg[sect][key]


def are_lists_equal(x, y) -> bool:
    return collections.Counter(x) == collections.Counter(y)


@patch("os.getuid", return_value=1)
def test_make_sudo_user(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    assert kb.make_sudo("test") == "test"


@patch("os.getuid", return_value=0)
def test_make_sudo_root(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    assert kb.make_sudo("test") == "sudo test"


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
    assert are_lists_equal(expected, actual) is True


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_syzkaller(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "syzkaller"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "syzkaller_args")


@patch("src.kernel_builder.KernelBuilder._run_ssh", return_value=0)
def test_get_params_generic(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "generic"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "generic_args")


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
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "generic_args").replace("-e DEBUG_KERNEL", kb.extra_args)

def test_add_modules() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.custom_modules = fetch_cfg_value_from_section_and_key(CUSTOM_MODULE, "kernel_builder", "custom_modules")
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    Path(p / MISC_DRVS_PATH).mkdir(parents=True)
    fst = "This is the 1st line.\n"
    lst = "This is the last line.\n"
    q = Path(p / MISC_DRVS_PATH / "Makefile")
    q.touch()
    q.write_text(fst)
    r = Path(p / MISC_DRVS_PATH / "Kconfig")
    r.touch()
    r.write_text(f"{fst}\n{lst}!")
    kb._add_modules()
    with open(q, "r") as f:
        data = f.readlines()
    assert data[-1] != fst
    with open(r, "r") as f:
        data = f.readlines()
    assert data[-1] == lst
    assert data[-2] != fst 



