from pathlib import Path
from types import SimpleNamespace

from likedbg.cli import build_pipeline
from likedbg.container_service import ContainerService
from likedbg.session import Session


def test_build_pipeline_includes_all_stage_names():
    sent: list[str] = []
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: sent.append(cmd))  # capture
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,
        workspace=Path("/ws"),
        kernel_volume="likedbg_ksrc",
        dl_dir=Path("/ws/kernels"),
        debugger_image="like_debugger:latest",
        ext="gef",
        panes=(1, 2),
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]
