from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debuggee import DebuggeeStage


def _ctx(mode):
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf" if mode == "native-host" else "tcg",
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    arch = "arm64" if mode == "native-host" else "x86_64"
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": arch}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/x/Image")
    return ctx


def test_native_debuggee_sends_plain_qemu_argv():
    sent = {}
    DebuggeeStage(send=lambda cmd: sent.setdefault("cmd", cmd), debuggee_image="like_debuggee:latest").run(
        _ctx("native-host")
    )
    assert sent["cmd"].startswith("qemu-system-aarch64")
    assert "docker run" not in sent["cmd"]


def test_in_container_debuggee_wraps_docker_run():
    sent = {}
    DebuggeeStage(send=lambda cmd: sent.setdefault("cmd", cmd), debuggee_image="like_debuggee:latest").run(
        _ctx("in-container")
    )
    assert sent["cmd"].startswith("docker run --rm -it -p 1234:1234")
    assert "like_debuggee:latest" in sent["cmd"]
    assert "qemu-system-x86_64" in sent["cmd"]
    assert "-v /ws/artifacts/x/Image:/ws/artifacts/x/Image:ro" in sent["cmd"]
