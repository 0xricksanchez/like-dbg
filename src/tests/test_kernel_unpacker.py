from ..kernel_unpacker import KernelUnpacker
from pathlib import Path


EMPTY_TARGZ = Path("src/tests/files/empty.tar.gz")
VALID_TARGZ = Path("src/tests/files/valid.tar.gz")
INVALID_TARGZ = Path("src/tests/files/invalid.tar.gz")


class MockUnpacker(KernelUnpacker):
    def __init__(self, archive: Path, kroot: Path) -> None:
        super().__init__(archive)
        self.kernel_root = kroot

    def set_no_unpack_opts(self, tmp_path: Path, is_vmlinux: bool, skip_prompts: bool):
        p = Path(tmp_path / "nounpack")
        p.mkdir()
        if is_vmlinux:
            (p / "vmlinux").touch()
        self.content = [x.name for x in p.iterdir()]
        self.archive = self.archive.absolute()
        self.ex_name = ".".join(self.archive.name.split(".")[:-2])
        self.skip_prompts = skip_prompts


def test_dst_empty(tmp_path) -> None:
    ku = MockUnpacker(EMPTY_TARGZ, tmp_path)
    assert ku._is_dest_empty() is True


def test_dst_not_empty(tmp_path) -> None:
    ku = MockUnpacker(EMPTY_TARGZ, tmp_path)
    (tmp_path / "dummy").touch()
    assert ku._is_dest_empty() is False


def test_is_not_vmlinux(tmp_path) -> None:
    ku = MockUnpacker(EMPTY_TARGZ, tmp_path)
    ku.content = [x.name for x in ku.kernel_root.iterdir()]
    assert ku._is_vmlinux() is not True


def test_is_vmlinux(tmp_path) -> None:
    ku = MockUnpacker(EMPTY_TARGZ, tmp_path)
    Path(f"{ku.kernel_root}/vmlinux").touch(exist_ok=True)
    ku.content = [x.name for x in ku.kernel_root.iterdir()]
    assert ku._is_vmlinux() is True


def test_unpack_targz_invalid(tmp_path) -> None:
    ku = MockUnpacker(INVALID_TARGZ, tmp_path)
    ku.ex_name = ".".join(ku.archive.name.split(".")[:-2])
    assert ku._unpack_targz() == 1


def test_unpack_targz_success(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, tmp_path)
    ku.archive = ku.archive.absolute()
    ku.ex_name = ".".join(ku.archive.name.split(".")[:-2])
    assert ku._unpack_targz() == 0


def test_fresh_unpack(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, tmp_path / "fresh_unpack")
    ku.archive = ku.archive.absolute()
    ku.ex_name = ".".join(ku.archive.name.split(".")[:-2])
    assert ku._fresh_unpack({})["status"] == "unpack"


def test_dirty_unpack(tmp_path) -> None:
    Path(tmp_path / "dirty").mkdir()
    ku = MockUnpacker(VALID_TARGZ, tmp_path / "dirty")
    ku.archive = ku.archive.absolute()
    ku.ex_name = ".".join(ku.archive.name.split(".")[:-2])
    assert ku._dirty_unpack({})["status"] == "unpack"


def test_no_unpack_vmlinux_and_reuse(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, Path("/tmp"))
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=True, skip_prompts=True)
    ret = ku._no_unpack({})
    assert ret["status"] == "reuse"
    assert ret["assume_dirty"] is False


def test_no_unpack_vmlinux_and_no_reuse(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, Path("/tmp"))
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=True, skip_prompts=False)
    ret = ku._no_unpack({})
    assert ret["status"] == "unpack"
    assert ret["assume_dirty"] is True


def test_no_unpack_no_vmlinux(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, Path("/tmp"))
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=False, skip_prompts=True)
    ret = ku._no_unpack({})
    assert ret["status"] == "unpack"
    assert ret["assume_dirty"] is True


def test_run_no_unpack_no_vmlinux(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, Path("/tmp"))
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=False, skip_prompts=True)
    ret = ku.run()
    assert ret["status"] == "unpack"
    assert ret["assume_dirty"] is True


def test_run_fresh_unpack(tmp_path) -> None:
    ku = MockUnpacker(VALID_TARGZ, tmp_path / "fresh_unpack")
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=False, skip_prompts=True)
    ret = ku.run()
    assert ret["status"] == "unpack"
    assert ret["assume_dirty"] is False


def test_run_dirty_unpack(tmp_path) -> None:
    Path(tmp_path / "dirty").mkdir()
    ku = MockUnpacker(VALID_TARGZ, tmp_path / "dirty")
    ku.set_no_unpack_opts(tmp_path, is_vmlinux=False, skip_prompts=True)
    ret = ku.run()
    assert ret["status"] == "unpack"
    assert ret["assume_dirty"] is False
