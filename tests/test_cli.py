from types import SimpleNamespace

from likedbg.cache import build_recipe
from likedbg.cache import rootfs_recipe
from likedbg.cli import build_pipeline
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.session import Session


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: None)
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        ext="gef",
        panes=(1, 2),
        build_recipe=br,
        rootfs_recipe=rr,
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]
