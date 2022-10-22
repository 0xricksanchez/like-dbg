from src.misc import (
    cross_compile,
    adjust_toolchain_arch,
    adjust_arch,
    adjust_qemu_arch,
    get_sha256_from_file,
    is_reuse,
    tmux,
    tmux_shell,
    _set_cfg,
    _set_base_cfg,
    _cherry_pick,
)
import pytest
import uuid
from pathlib import Path
import configparser
import subprocess as sp
from unittest.mock import MagicMock, patch, Mock

MMP_INI = Path("src/tests/confs/lkdl_mmp.ini")
CFG_INI = Path("src/tests/confs/cfg_setter.ini")


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
    assert m.baz == "False"
    assert "tag" not in vars(m)
    assert "mmp" not in vars(m)
    assert "commit" in vars(m)


def test_set_base_cfg_ignore_empty() -> None:
    m = Mock()
    cfg = configparser.ConfigParser()
    cfg.read(CFG_INI)
    _set_base_cfg(cfg, [], m, ["debuggee", "kernel_dl"], ignore_empty=True)
    assert "tag" not in vars(m)
    assert "mmp" not in vars(m)
    assert "commit" not in vars(m)
