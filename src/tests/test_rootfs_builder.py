from pathlib import Path

from src.docker_runner import DockerRunner
from src.rootfs_builder import RootFSBuilder
from unittest.mock import patch, MagicMock


def test_is_exist_fail() -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.rootfs_path = Path("/foobar")
    assert rfsb.is_exist() is False


def test_is_exist_success(tmp_path) -> None:
    Path(tmp_path / "foobar").touch()
    rfsb = RootFSBuilder(False, **{"kroot": tmp_path})
    rfsb.rootfs_path = tmp_path / "foobar"
    assert rfsb.is_exist() is True


def test_run_container_full_cfg() -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    rfsb.run_container()
    rfsb.client.containers.run.assert_called_with(
        None,
        volumes={f"{Path.cwd() / 'io'}": {"bind": f"{rfsb.docker_mnt}", "mode": "rw"}},
        detach=True,
        privileged=True,
        remove=True,
        command=f"/bin/bash -c 'set -e; . /home/{rfsb.user}/rootfs.sh -n {rfsb.fs_name} -a x86_64 -d {rfsb.distribution} -p {rfsb.packages} -u {rfsb.user} -h {rfsb.hostname.strip()}'",
    )


def test_run_container_no_hostname() -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.hostname = ""
    rfsb.client = MagicMock()
    rfsb.run_container()
    rfsb.client.containers.run.assert_called_with(
        None,
        volumes={f"{Path.cwd() / 'io'}": {"bind": f"{rfsb.docker_mnt}", "mode": "rw"}},
        detach=True,
        privileged=True,
        remove=True,
        command=f"/bin/bash -c 'set -e; . /home/{rfsb.user}/rootfs.sh -n {rfsb.fs_name} -a x86_64 -d {rfsb.distribution} -p {rfsb.packages} -u {rfsb.user}'",
    )


@patch.object(DockerRunner, "get_image", return_value="foobar")
def test__run(mock) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    rfsb._run()
    assert rfsb.image == "foobar"


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_run_is_reuse(tflush, gimg) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    assert rfsb.run() is None


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch.object(DockerRunner, "build_image", return_value=None)
def test_run_update(bimg, gimg) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.hostname = ""
    rfsb.update_containers = True
    assert rfsb.run() is None


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch.object(DockerRunner, "build_image", return_value=None)
def test_run_frebuild(bimg, gimg) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    rfsb.hostname = ""
    rfsb.update_containers = False
    rfsb.force_rebuild = True
    assert rfsb.run() is None
    assert rfsb.image == "foobar"


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch.object(DockerRunner, "build_image", return_value=None)
def test_run_partial(bimg, gimg) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    rfsb.hostname = ""
    rfsb.update_containers = False
    rfsb.force_rebuild = False
    rfsb.partial = True
    assert rfsb.run() is None
    assert rfsb.image == "foobar"


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch.object(DockerRunner, "build_image", return_value=None)
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "n")
def test_run_skip_prompts(tflush, bimg, gimg, tmp_path) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    p = tmp_path / "rootfs"
    p.touch()
    rfsb.rootfs_path = p
    rfsb.hostname = ""
    rfsb.update_containers = False
    rfsb.force_rebuild = False
    rfsb.partial = False
    rfsb.skip_prompts = True
    assert rfsb.run() is None


@patch.object(DockerRunner, "get_image", return_value="foobar")
@patch.object(DockerRunner, "build_image", return_value=None)
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "n")
def test_run_else(tflush, bimg, gimg, tmp_path) -> None:
    rfsb = RootFSBuilder(False, **{"kroot": "/tmp"})
    rfsb.client = MagicMock()
    p = tmp_path / "rootfs"
    p.touch()
    rfsb.rootfs_path = p
    rfsb.hostname = ""
    rfsb.update_containers = False
    rfsb.force_rebuild = False
    rfsb.partial = False
    rfsb.skip_prompts = False
    assert rfsb.run() is None
