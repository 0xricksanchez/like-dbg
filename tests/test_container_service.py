from types import SimpleNamespace

import docker.errors
import pytest
from loguru import logger

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


class FakeApi:
    def __init__(self, chunks=(b"ok\n",), exit_code=0):
        self.chunks, self.exit_code = chunks, exit_code
        self.created = None
        self.start_kwargs = None

    def exec_create(self, container, cmd, workdir=None, tty=False):
        self.created = {"container": container, "cmd": cmd, "workdir": workdir, "tty": tty}
        return {"Id": "e1"}

    def exec_start(self, exec_id, tty=False, stream=False):
        self.start_kwargs = {"tty": tty, "stream": stream}
        return iter(self.chunks)

    def exec_inspect(self, exec_id):
        return {"ExitCode": self.exit_code}


def _svc_with_api(chunks=(b"ok\n",), exit_code=0):
    client = FakeClient()
    client.api = FakeApi(chunks, exit_code)
    return ContainerService(client), client.api


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


def test_exec_streams_returns_result_and_logs(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="DEBUG", format="{message}")
    try:
        svc, api = _svc_with_api(chunks=[b"line1\n", b"line2\n"], exit_code=0)
        res = svc.exec(SimpleNamespace(id="c1"), "true", workdir="/io")
        logger.complete()
    finally:
        logger.remove(sink)
    assert res.exit_code == 0
    assert res.output == "line1\nline2\n"
    assert api.created["cmd"] == ["/bin/sh", "-c", "true"] and api.created["workdir"] == "/io"
    assert api.created["tty"] is True and api.start_kwargs["tty"] is True
    assert any("line1" in m for m in msgs) and any("line2" in m for m in msgs)


def test_exec_raises_on_nonzero_with_tail():
    svc, _ = _svc_with_api(chunks=[b"boom\n"], exit_code=2)
    with pytest.raises(ContainerError) as exc:
        svc.exec(SimpleNamespace(id="c1"), "false")
    assert "boom" in str(exc.value)


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
