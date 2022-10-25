from pathlib import Path
from src.debugger import GDB_SCRIPT_HIST, Debugger
from unittest.mock import patch
import hashlib

TPATH = Path("/tmp/.hist")
TPATH_NEW = Path("/tmp/.hist_new")
PACKED_KERNEL = Path("src/tests/files/testKernel_packed")


def test_is_gdb_script_success() -> None:
    d = Debugger(**{"kroot": "foo"})
    GDB_SCRIPT_HIST.touch()
    assert d._is_gdb_script_hist() is True


@patch("src.debugger.GDB_SCRIPT_HIST", Path("/tmp/.fake_file"))
def test_is_gdb_script_fail() -> None:
    d = Debugger(**{"kroot": "foo"})
    assert d._is_gdb_script_hist() is False


@patch("src.debugger.GDB_SCRIPT_HIST", TPATH)
def test_handle_gdb_change_update_existing() -> None:
    d = Debugger(**{"kroot": "foo"})
    d.force_rebuild = False
    TPATH.touch()
    d.gdb_script = Path("/tmp/.hist2")
    d.gdb_script.touch()
    cntn = "start\nbreak *0xdeadbeef\ncontinue"
    d.gdb_script.write_text(cntn)
    d._handle_gdb_change()
    assert d.force_rebuild is True
    assert TPATH.read_text() == hashlib.sha256(cntn.encode()).hexdigest()
    TPATH.unlink()
    d.gdb_script.unlink()


@patch("src.debugger.GDB_SCRIPT_HIST", TPATH_NEW)
def test_handle_gdb_change_new() -> None:
    d = Debugger(**{"kroot": "foo"})
    d.force_rebuild = False
    d.gdb_script = Path("/tmp/.hist2")
    d.gdb_script.touch()
    cntn = "start\nbreak *0xdeadbeef\ncontinue"
    d.gdb_script.write_text(cntn)
    d._handle_gdb_change()
    assert d.force_rebuild is False
    assert TPATH_NEW.read_text() == hashlib.sha256(cntn.encode()).hexdigest()
    d.gdb_script.unlink()
    TPATH_NEW.unlink()


def test_set_ctf_ctx_in_init(tmp_path) -> None:
    d = Debugger(**{"kroot": "foo", "ctf_ctx": True, "ctf_dir": tmp_path, "ctf_kernel": PACKED_KERNEL})
    assert d.ctf is True


def test_set_ctf_ctx(tmp_path) -> None:
    d = Debugger(**{"kroot": "foo"})
    d.ctf_dir = tmp_path
    d._set_ctf_ctx({"ctf_kernel": PACKED_KERNEL})
    assert d.ctf is False


def test_extract_vmlinux_success(tmp_path) -> None:
    d = Debugger(**{"kroot": "foo"})
    d.ctf_kernel = PACKED_KERNEL
    d.ctf_dir = tmp_path
    assert d._extract_vmlinux() == 0


def test_extract_vmlinux_fail(tmp_path) -> None:
    d = Debugger(**{"kroot": "foo"})
    p = Path(tmp_path / "fake_kernel")
    p.touch()
    d.ctf_kernel = p
    d.ctf_dir = tmp_path
    assert d._extract_vmlinux() == 1


@patch("src.misc.tmux", return_value=None)
@patch("src.misc.tmux_shell")
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_run_container(tflush, tsmock, tmock) -> None:
    d = Debugger(**{"kroot": "foo"})
    d.project_dir = "/some/project_dir"
    d.tag = "tag"
    d.run_container()
    expected = f"send-keys 'docker run -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {d.project_dir}:{d.docker_mnt} --net=\"host\" {d.tag} /bin/bash -c \"set -e; . /home/user/debugger.sh -a {d.arch} -p /io -c 0 -g /home/user/gdb_script\"' 'C-m'"
    tmock.assert_called_with(expected)
