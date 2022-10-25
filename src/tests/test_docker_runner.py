from docker.models.containers import Container
from docker import DockerClient
from ..docker_runner import DockerRunner
from pathlib import Path
from unittest.mock import patch, Mock
import pytest
import uuid
import shutil

GENERIC_ARGS = {
    "skip_prompts": False,
    "ctf_ctx": False,
    "log_level": "ERROR",
    "user_cfg": "",
    "update_containers": False,
}

MOCK_UNPACKER_RES = {
    "kroot": "mock_path",
    "status": "unpack",
}

DOCKERFILE = Path("src/tests/files/.dockerfile_test")


class MockDockerRunner(DockerRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.force_rebuild = False

    def run_container(self, repo: str, tag: str, entrypoint_cmd: str) -> Container:
        self.container = self.client.containers.run(f"{repo}:{tag}", entrypoint_cmd, detach=True)
        return self.container


def test_pull_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.pull_image("busybox", "latest") is not None


def test_get_image_exists() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.get_image(tag="busybox") is not None


def test_get_image_not_exists() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.get_image(tag="like_dbg_not_exist") is None


def test_is_base_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.tag_base_image = "busybox"
    assert dr.is_base_image() is True


def test_is_not_base_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.tag_base_image = "like_dbg_not_base"
    assert dr.is_base_image() is False


def test_build_base_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile_base_image = str(DOCKERFILE)
    dr.tag_base_image = "a_base_img"
    assert dr.build_base_img() == 0


def test_list_running_containers_is_empty() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.list_running_containers() == []


def test_run_container_success() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert mdr.run_container("busybox", "latest", "/bin/true") is not None


def test_list_running_containers_is_one() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.run_container("ubuntu", "latest", "tail -f /dev/null")
    assert len(mdr.list_running_containers()) > 0
    mdr.stop_container()


def test_stop_container() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    old_len = len(mdr.list_running_containers())
    mdr.run_container("ubuntu", "latest", "tail -f /dev/null")
    mdr.stop_container()
    new_len = len(mdr.list_running_containers()) > 0
    assert old_len == new_len


def test_wait_for_container() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.run_container("busybox", "latest", "/bin/true")
    ret = mdr.wait_for_container()
    assert ret["StatusCode"] == 0


def test_check_existing_ok() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.skip_prompts = True
    mdr.tag = "busybox"
    assert mdr.check_existing().tags == ["busybox:latest"]


def test_check_existing_update_containers() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.update_containers = True
    assert mdr.check_existing() is None


def test_check_existing_force_rebuild() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.update_containers = False
    mdr.force_rebuild = True
    assert mdr.check_existing() is None


def test_build_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    assert dr.build_image() == 0


def test_build_image_update() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    dr.update_containers = True
    assert dr.build_image() == 0


def test_run_update() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    dr.update_containers = True
    assert dr.run() == 1


def test_run_check_existing() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    dr.update_containers = False
    dr.skip_prompts = True
    dr.force_rebuild = False
    dr.tag = "busybox"
    assert dr.run(check_existing=True) == 0


@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_check_existing_is_reuse(self) -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.skip_prompts = False
    mdr.force_rebuild = False
    mdr.update_containers = False
    mdr.tag = "busybox"
    assert mdr.check_existing().tags == ["busybox:latest"]


@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "n")
def test_check_existing_no_reuse(self) -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.skip_prompts = False
    mdr.force_rebuild = False
    mdr.update_containers = False
    mdr.tag = "busybox"
    assert mdr.check_existing() is None


def test_run_no_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    dr.tag = "busybox"
    dr.update_containers = False
    assert dr.run(check_existing=False) == 0


@patch("src.docker_runner.DockerRunner.is_base_image", return_value=False)
def test_run_no_base_image(self) -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.dockerfile = str(DOCKERFILE)
    dr.tag = "busybox"
    dr.update_containers = False
    dr.image = False
    assert dr.run(check_existing=False) == 0


def test_guarantee_new_ssh() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    assert dr.guarantee_ssh(p) == p
    shutil.rmtree(p)


def test_no_kroot() -> None:
    with pytest.raises(SystemExit) as ext:
        _ = DockerRunner(**GENERIC_ARGS)
    assert ext.type == SystemExit
    assert ext.value.code == -1


@patch("time.sleep", return_value=None)
@patch("fabric.Connection", return_value=Mock)
def test_init_ssh_fail_missing_port(fab, slp) -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.client = DockerClient()
    with pytest.raises((Exception, SystemExit)) as err:
        dr.init_ssh()
        assert err.type == SystemExit
        assert err.value.code == -1


@patch("fabric.Connection", return_value=Mock)
@patch("time.sleep", return_value=None)
def test_init_ssh_fail_sucess(fab, slp) -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.client = DockerClient()
    dr.ssh_fwd_port = 1337
    dr.user = "user"
    dr.init_ssh()
    assert dr.ssh_conn.host == "localhost"
    assert dr.ssh_conn.port == 1337
