from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debuggee import DebuggeeStage


def _ctx():
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
        ssh_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": "arm64"}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/linux-6.6.30/Image")
    return ctx


def test_native_debuggee_launches_qemu_argv():
    launched = {}
    stage = DebuggeeStage(launch=lambda argv: launched.setdefault("argv", argv))
    stage.run(_ctx())
    assert launched["argv"][0] == "qemu-system-aarch64"
    assert "-kernel" in launched["argv"]
