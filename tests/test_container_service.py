from types import SimpleNamespace

import docker.errors
import pytest

from likedbg.container_service import ContainerService
from likedbg.errors import ContainerError


class FakeImages:
    def __init__(self, existing):
        self._existing = existing

    def get(self, tag):
        if tag in self._existing:
            return SimpleNamespace(tags=[tag])
        raise docker.errors.ImageNotFound(tag)


class FakeContainers:
    def __init__(self):
        self.run_kwargs = None

    def run(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c123")


class FakeClient:
    def __init__(self, existing=()):
        self.images = FakeImages(set(existing))
        self.containers = FakeContainers()


def test_image_exists_true_false():
    svc = ContainerService(FakeClient(existing=["like_kbuilder_arm64"]))
    assert svc.image_exists("like_kbuilder_arm64") is True
    assert svc.image_exists("nope") is False


def test_run_detached_passes_through():
    client = FakeClient()
    svc = ContainerService(client)
    handle = svc.run_detached("img", detach=True, tty=True)
    assert handle.id == "c123"
    assert client.containers.run_kwargs["image"] == "img"


def test_exec_returns_result_on_success():
    container = SimpleNamespace(exec_run=lambda cmd, workdir=None: SimpleNamespace(exit_code=0, output=b"ok\n"))
    svc = ContainerService(FakeClient())
    res = svc.exec(container, "true")
    assert res.exit_code == 0
    assert res.output == "ok\n"


def test_exec_raises_on_nonzero():
    container = SimpleNamespace(exec_run=lambda cmd, workdir=None: SimpleNamespace(exit_code=2, output=b"boom"))
    svc = ContainerService(FakeClient())
    with pytest.raises(ContainerError):
        svc.exec(container, "false")
