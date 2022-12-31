import configparser
import subprocess as sp
import uuid
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.debuggee import Debuggee
from src.debugger import Debugger
from src.kernel_builder import KernelBuilder
from src.misc import (
    SYSTEM_CFG,
    _cherry_pick,
    _set_base_cfg,
    _set_cfg,
    adjust_arch,
    adjust_qemu_arch,
    adjust_toolchain_arch,
    cfg_setter,
    cross_compile,
    get_sha256_from_file,
    get_value_from_section_by_key,
    is_reuse,
    new_context,
    tmux,
    tmux_shell,
)
from src.rootfs_builder import RootFSBuilder

MMP_INI = Path("src/tests/confs/lkdl_mmp.ini")
CFG_INI = Path("src/tests/confs/cfg_setter.ini")
USR_INI = Path("src/tests/confs/user.ini")


def test_cross_compile() -> None:
    assert cross_compile("arm64") == "aarch64-linux-gnu-"
    assert cross_compile("riscv64") == "riscv64-linux-gnu-"
    assert cross_compile("X8664") == "x86_64-pc-linux-gnu-"


def test_adjust_toolchain_arch() -> None:
    assert adjust_toolchain_arch("arm64") == "aarch64"
    assert adjust_toolchain_arch("x86_64") == "x86-64"
    assert adjust_toolchain_arch("foo") == "foo"


def test_adjust_arch() -> None:
    assert adjust_arch("riscv64") == "riscv"
    assert adjust_arch("x86_64") == "x86_64"
    assert adjust_arch("arm64") == "arm64"
    with pytest.raises(SystemExit) as ext:
        adjust_arch("foo")
    assert ext.type == SystemExit
    assert ext.value.code == -1


def test_adjust_qemu_arch() -> None:
    assert adjust_qemu_arch("arm64") == "aarch64"
    assert adjust_qemu_arch("foo") == "foo"


def test_get_sha256_from_file() -> None:
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    p.touch()
    p.write_text("FOOBAR")
    assert get_sha256_from_file(p) == "24c422e681f1c1bd08286c7aaf5d23a5f088dcdb0b219806b3a9e579244f00c5"
    p.unlink()


@patch.object(sp, "run")
def test_tmux(mock_m) -> None:
    cmd = "foo --bar --baz qux"
    tmux(cmd)
    mock_m.assert_called_with(f"tmux {cmd} > /dev/null", shell=True)


@patch("src.misc.tmux")
def test_tmux_shell(mock_m) -> None:
    cmd = "foo --bar --baz qux"
    tmux_shell(cmd)
    mock_m.assert_called_with("send-keys 'foo --bar --baz qux' 'C-m'")


@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_is_reuse(self) -> None:
    assert is_reuse("foo") is True


@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "n")
def test_is_not_reuse(self) -> None:
    assert is_reuse("foo") is False


def test_set_cfg() -> None:
    m = MagicMock
    cfg = configparser.ConfigParser()
    cfg.read(MMP_INI)
    _set_cfg(cfg, m, "kernel_dl", "mmp", ignore_empty=False)
    assert m.mmp == "5.15.67"


def test_set_cfg_not_ignore_empty() -> None:
    m = MagicMock
    m.tag = "foo"
    cfg = configparser.ConfigParser()
    cfg.read(MMP_INI)
    _set_cfg(cfg, m, "kernel_dl", "tag", ignore_empty=False)
    assert m.tag == ""


def test_set_cfg_ignore_empty() -> None:
    m = MagicMock
    m.tag = "foo"
    cfg = configparser.ConfigParser()
    cfg.read(MMP_INI)
    _set_cfg(cfg, m, "kernel_dl", "tag", ignore_empty=True)
    assert m.tag == "foo"


def test_cherry_pick() -> None:
    m = MagicMock
    cfg = configparser.ConfigParser()
    cfg.read(CFG_INI)
    _cherry_pick(cfg, {"debuggee": ["foo", "baz"], "debugger": ["qux"]}, m, ignore_empty=True)
    assert m.foo == "Bar"
    assert hasattr(m, "qux") is False


def test_set_base_cfg() -> None:
    m = Mock()
    cfg = configparser.ConfigParser()
    cfg.read(CFG_INI)
    _set_base_cfg(cfg, ["mmp", "tag"], m, ["debuggee", "kernel_dl", "foobar"], ignore_empty=False)
    assert m.foo == "Bar"
    assert m.panic == "foo"
    assert "tag" not in vars(m)
    assert "mmp" not in vars(m)
    assert "commit" in vars(m)


def test_set_base_cfg_ignore_empty() -> None:
    m = Mock()
    cfg = configparser.ConfigParser()
    cfg.read(CFG_INI)
    _set_base_cfg(cfg, [], m, ["debuggee", "kernel_dl"], ignore_empty=True)
    assert "tag" not in vars(m)
    assert "mmp" in vars(m)
    assert "commit" not in vars(m)


@patch("src.misc.CFGS", [CFG_INI])
def test_cfg_setter() -> None:
    m = Mock()
    cfg_setter(m, sections=["kernel_dl"], user_cfg=str(USR_INI), exclude_keys=["ignore_me"], cherry_pick={"debuggee": ["panic"]})
    assert "ignore_me" not in vars(m)
    assert m.mmp == "5.15.67"
    assert m.panic == "foo"


def test_new_context(tmp_path) -> None:
    initial_path = Path.cwd()

    @new_context(tmp_path)
    def with_decorator():
        return Path.cwd()

    assert with_decorator() == tmp_path
    assert Path.cwd() == initial_path


def test_cfg_setter_kbuilder() -> None:
    kb = KernelBuilder(**{"kroot": "foo", "user_cfg": CFG_INI})
    assert kb.arch == "arm64"
    assert kb.compiler == "compiler"


def test_cfg_setter_rootfs() -> None:
    rfs = RootFSBuilder(**{"kroot": "foo", "user_cfg": CFG_INI})
    assert rfs.rootfs_ftype == "ext4"
    assert rfs.arch == "arm64"


def test_cfg_setter_debugger() -> None:
    d = Debugger(**{"kroot": "foo", "user_cfg": CFG_INI})
    assert d.gdb_script == "some/path"
    assert d.arch == "arm64"


def test_cfg_setter_debuggee() -> None:
    d = Debuggee(**{"kroot": "foo", "user_cfg": CFG_INI})
    assert d.rootfs_ftype == "ext4"
    assert d.arch == "arm64"
    assert d.panic == "foo"


def test_get_value_from_section_by_key() -> None:
    assert get_value_from_section_by_key(SYSTEM_CFG, "debuggee_docker", "tag") == "like_debuggee"
