from pathlib import Path
from src.rootfs_builder import RootFSBuilder


def test_is_exist_fail() -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    assert rfsb.is_exist() is False


def test_is_exist_success(tmp_path) -> None:
    Path(tmp_path / "foobar").touch()
    rfsb = RootFSBuilder(False, **{"kroot": tmp_path})
    rfsb.rootfs_path = tmp_path / "foobar"
    assert rfsb.is_exist() is True
