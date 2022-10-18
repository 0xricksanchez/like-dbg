from docker.models.containers import Container
from ..docker_runner import DockerRunner

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


class MockDockerRunner(DockerRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def run_container(self, entrypoint_cmd: str) -> Container:
        self.container = self.client.containers.run("ubuntu:latest", entrypoint_cmd, detach=True)
        return self.container


def test_get_image_exists() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.get_image(tag="like_dbg_base") != None


def test_get_image_not_exists() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.get_image(tag="like_dbg_not_exist") == None


def test_is_base_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.tag_base_image = "like_dbg_base"
    assert dr.is_base_image() is True


def test_is_not_base_image() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    dr.tag_base_image = "like_dbg_not_base"
    assert dr.is_base_image() is False


def test_list_running_containers_is_empty() -> None:
    dr = DockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert dr.list_running_containers() == []


def test_run_container_sucess() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    assert mdr.run_container("/bin/true") != None


def test_list_running_containers_is_one() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.run_container("tail -f /dev/null")
    assert len(mdr.list_running_containers()) > 0
    mdr.stop_container()


def test_stop_container() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    old_len = len(mdr.list_running_containers())
    mdr.run_container("tail -f /dev/null")
    mdr.stop_container()
    new_len = len(mdr.list_running_containers()) > 0
    assert old_len == new_len


def test_wait_for_container() -> None:
    mdr = MockDockerRunner(**GENERIC_ARGS | MOCK_UNPACKER_RES)
    mdr.run_container("/bin/true")
    ret = mdr.wait_for_container()
    assert ret["StatusCode"] == 0
