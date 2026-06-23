from types import SimpleNamespace

import docker.errors
import pytest

from likedbg.container_service import ContainerService
from likedbg.errors import ContainerError


class FakeImages:
    def __init__(self, existing=(), labels=None):
        self._existing = set(existing)
        self._labels = labels or {}
        self.build_kwargs = None

    def get(self, tag):
        if tag in self._existing:
            return SimpleNamespace(tags=[tag], labels=self._labels.get(tag, {}))
        raise docker.errors.ImageNotFound(tag)

    def build(self, **kwargs):
        self.build_kwargs = kwargs
        return SimpleNamespace(id="built"), iter([])


class FakeContainers:
    def __init__(self):
        self.run_kwargs = None

    def run(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c123")


class FakeClient:
    def __init__(self, existing=(), labels=None):
        self.images = FakeImages(set(existing), labels)
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


def test_exec_wraps_command_in_shell():
    # Build commands use $(nproc) and && — they must run through a shell, not as a bare argv.
    captured = {}

    def exec_run(cmd, workdir=None):
        captured["cmd"] = cmd
        captured["workdir"] = workdir
        return SimpleNamespace(exit_code=0, output=b"")

    svc = ContainerService(FakeClient())
    svc.exec(SimpleNamespace(exec_run=exec_run), "make -j$(nproc) all", workdir="/io/linux")
    assert captured["cmd"] == ["/bin/sh", "-c", "make -j$(nproc) all"]
    assert captured["workdir"] == "/io/linux"


def test_run_detached_defaults_to_auto_remove():
    client = FakeClient()
    svc = ContainerService(client)
    svc.run_detached("img", detach=True, tty=True)
    assert client.containers.run_kwargs["auto_remove"] is True


def test_run_detached_auto_remove_can_be_overridden():
    client = FakeClient()
    svc = ContainerService(client)
    svc.run_detached("img", auto_remove=False, detach=True, tty=True)
    assert client.containers.run_kwargs["auto_remove"] is False


def test_build_image_forwards_labels_and_args():
    client = FakeClient()
    svc = ContainerService(client)
    svc.build_image(".dockerfile_base", "like_dbg_base:latest", {"USER": "user"}, labels={"likedbg.input_sha": "abc"})
    kw = client.images.build_kwargs
    assert kw["dockerfile"] == ".dockerfile_base"
    assert kw["tag"] == "like_dbg_base:latest"
    assert kw["buildargs"] == {"USER": "user"}
    assert kw["labels"] == {"likedbg.input_sha": "abc"}


def test_image_labels_returns_image_labels():
    svc = ContainerService(FakeClient(existing=["t:latest"], labels={"t:latest": {"likedbg.input_sha": "xyz"}}))
    assert svc.image_labels("t:latest") == {"likedbg.input_sha": "xyz"}


def test_image_labels_missing_image_raises():
    svc = ContainerService(FakeClient())
    with pytest.raises(ContainerError):
        svc.image_labels("nope:latest")
