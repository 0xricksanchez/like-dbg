from pathlib import Path

from src.debuggee import Debuggee
from unittest.mock import patch, MagicMock
import pytest


@patch("subprocess.run")
def test_infer_qemu_fs_mount_cpio(sp_mock) -> None:
    d = Debuggee(**{"kroot": "foo"})
    mock = MagicMock()
    mock.configure_mock(**{"stdout": b"A cpio archive dummy archive"})
    sp_mock.return_value = mock
    assert d.infer_qemu_fs_mount() == f" -initrd {d.rootfs}"


@patch("subprocess.run")
def test_infer_qemu_fs_mount_filesystem(sp_mock) -> None:
    d = Debuggee(**{"kroot": "foo"})
    mock = MagicMock()
    mock.configure_mock(**{"stdout": b"Some filesystem data..."})
    sp_mock.return_value = mock
    assert d.infer_qemu_fs_mount() == f" -drive file={d.rootfs},format=raw"


@patch("subprocess.run")
def test_infer_qemu_fs_mount_error(sp_mock) -> None:
    d = Debuggee(**{"kroot": "foo"})
    mock = MagicMock()
    mock.configure_mock(**{"stdout": b"foo bar baz"})
    sp_mock.return_value = mock
    with pytest.raises(SystemExit) as ext:
        d.infer_qemu_fs_mount()
        assert ext.type == SystemExit
        assert ext.value.code == -1


@patch("subprocess.run")
def test_infer_qemu_fs_mount_cpio_ctf(sp_mock) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": True})
    mock = MagicMock()
    mock.configure_mock(**{"stdout": b"A cpio archive dummy archive"})
    sp_mock.return_value = mock
    assert d.infer_qemu_fs_mount() == f" -initrd {d.rootfs.name}"


def test_assert_ctf_ctx_mode() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": True, "ctf_mount": "/foo", "ctf_kernel": "/a/path", "ctf_fs": "/another/path"})
    assert d.ctf is True
    assert d.ctf_mount == "/foo"
    assert d.kernel == Path("/a/path")
    assert d.rootfs == Path("/another/path")


@patch("src.misc.cfg_setter", return_value=None)
def test_assert_normal_mode(self) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.kernel_root = "/foo"
    d.arch = "x86_64"
    d.rootfs_ftype = ""
    assert d.ctf is False
    assert d.kernel == Path(f"{d.docker_mnt}/{d.kernel_root}/arch/{d.arch}/boot/Image")
    assert d.rootfs == Path(f"{d.docker_mnt}/{d.rootfs_dir}/{d.rootfs_base + d.arch + d.rootfs_ftype}")


def test_infer_panic_behavior_panic() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "reboot"
    assert d.infer_panic_behavior() == -1


def test_infer_panic_behavior_halt() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "halt"
    assert d.infer_panic_behavior() == 0


def test_infer_panic_behavior_wait_90() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "wait 90"
    assert d.infer_panic_behavior() == 90


def test_infer_panic_behavior_wait_split_fail() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "wait"
    assert d.infer_panic_behavior() == 15


def test_infer_panic_behavior_wait_conversion_fail() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "wait a"
    assert d.infer_panic_behavior() == 15


def test_infer_panic_behavior_wait_unknown() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.panic = "foo"
    with pytest.raises(SystemExit) as ext:
        d.infer_panic_behavior()
        assert ext.type == SystemExit
        assert ext.value.code == -1


def test_add_smep() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.smep = True
    d.smap = False
    tmp = "some cmd -cpu foo"
    d.cmd = tmp
    d._add_smep_smap()
    assert d.cmd == f"{tmp},+smep"


def test_add_smap() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.smep = False
    d.smap = True
    tmp = "some cmd -cpu foo"
    d.cmd = tmp
    d._add_smep_smap()
    assert d.cmd == f"{tmp},+smap"


def test_add_smep_smap() -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.smep = True
    d.smap = True
    tmp = "some cmd -cpu foo"
    d.cmd = tmp
    d._add_smep_smap()
    assert d.cmd == f"{tmp},+smep,+smap"


@patch("src.misc.tmux")
@patch("src.misc.tmux_shell")
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
@patch.object(Debuggee, "infer_qemu_fs_mount", return_value=" -initrd /foo/bar.cpio")
def test_run_x86_all_mitigations_kvm_gdb(tmock, tsmock, infer_mock, flush_mock) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.kaslr = True
    d.smep = True
    d.smap = True
    d.kpti = True
    d.kvm = True
    d.arch = "x86_64"
    d.kernel = "/some/kernel/Image"
    d.rootfs = Path("/foo/rootfs")
    d.run()
    assert (
        d.cmd
        == 'qemu-system-x86_64 -m 1024 -smp 1 -kernel /some/kernel/Image -cpu qemu64,+smep,+smap -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 kaslr pti=on oops=panic panic=0" -initrd /foo/bar.cpio -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid -enable-kvm -S -s'
    )


@patch("src.misc.tmux")
@patch("src.misc.tmux_shell")
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
@patch.object(Debuggee, "infer_qemu_fs_mount", return_value=" -initrd /foo/bar.cpio")
def test_run_x86_no_mitigations_kvm_gdb(tmock, tsmock, infer_mock, flush_mock) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.kaslr = False
    d.smep = False
    d.smap = False
    d.kpti = False
    d.kvm = False
    d.gdb = False
    d.arch = "x86_64"
    d.kernel = "/some/kernel/Image"
    d.rootfs = Path("/foo/rootfs")
    d.run()
    assert (
        d.cmd
        == 'qemu-system-x86_64 -m 1024 -smp 1 -kernel /some/kernel/Image -cpu qemu64 -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr nosmep nosmap nopti oops=panic panic=0" -initrd /foo/bar.cpio -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid'
    )


@patch("src.misc.tmux")
@patch("src.misc.tmux_shell")
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
@patch.object(Debuggee, "infer_qemu_fs_mount", return_value=" -initrd /foo/bar.cpio")
def test_run_arm_no_mitigations_kvm_on(tmock, tsmock, infer_mock, flush_mock) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.kaslr = False
    d.smep = False
    d.smap = False
    d.kpti = False
    d.kvm = True
    d.gdb = False
    d.qemu_arch = "aarch64"
    d.kernel = "/some/kernel/Image"
    d.rootfs = Path("/foo/rootfs")
    d.run()
    assert (
        d.cmd
        == 'qemu-system-aarch64 -m 1024 -smp 1 -kernel /some/kernel/Image -cpu cortex-a72 -machine type=virt -append "console=ttyAMA0 root=/dev/vda earlyprintk=serial net.ifnames=0 nokaslr nosmep nosmap nopti oops=panic panic=0" -initrd /foo/bar.cpio -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid'
    )


@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_run_unknown_arch(flush_mock) -> None:
    d = Debuggee(**{"kroot": "foo", "ctf_ctx": False})
    d.qemu_arch = "foobar"
    with pytest.raises(SystemExit) as ext:
        d.run()
        assert ext.type == SystemExit
        assert ext.value.code == -1
