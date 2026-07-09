from pathlib import Path
from types import SimpleNamespace

import pytest
from loguru import logger

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import load_manifest
from likedbg.cache import manifest_exists
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import UnpackError
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.unpack import UnpackStage


class FakeContainerService(ContainerService):
    def __init__(self):
        self.execs = []
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _recipe(**overrides) -> BuildRecipe:
    kwargs: dict = {
        "version": "6.6.30",
        "arch": "arm64",
        "compiler": "gcc",
        "make_vars": (("ARCH", "arm64"), ("CROSS_COMPILE", "aarch64-linux-gnu-")),
        "frag_hashes": (),
        "fragments": (),
        "patch_hashes": (),
        "kernel_tag": "gef",
    }
    kwargs.update(overrides)
    return BuildRecipe(**kwargs)


def _ctx(storage_mode: str, tmp_path: Path) -> PipelineContext:
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode=storage_mode,
        gdbstub_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = tmp_path / "linux-6.6.30.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    return ctx


def _write_patch(workspace: Path, rel_dir: str, name: str) -> None:
    pdir = workspace / rel_dir
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / name).write_text("--- a\n+++ b\n")


def test_volume_mode_mounts_named_volume(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, recipe=_recipe(), kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert "likedbg_ksrc" in mounts


def test_extract_command_issued_and_source_root_set(tmp_path):
    svc = FakeContainerService()
    recipe = _recipe()
    out = UnpackStage(svc, recipe=recipe, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    assert any("tar" in c for c in svc.execs)
    assert out.source_root is not None and recipe.src_label in str(out.source_root)
    assert out.srckey == recipe.src_key


def test_archive_outside_workspace_raises_unpack_error(tmp_path):
    """Archive not under workspace should raise UnpackError with an actionable remedy."""
    ws = tmp_path / "ws"
    ws.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    host = HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="bind",
        gdbstub_addr="host.docker.internal",
    )
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = elsewhere / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    with pytest.raises(UnpackError, match="not under the workspace"):
        UnpackStage(FakeContainerService(), recipe=_recipe(), kernel_volume="likedbg_ksrc", workspace=ws).run(ctx)


def test_unpack_reuses_when_source_manifest_present(tmp_path):
    recipe = _recipe()
    write_manifest(
        tmp_path,
        Manifest(
            kind="source",
            label=recipe.src_label,
            key=recipe.src_key,
            version=recipe.version,
            arch="",
        ),
    )
    svc = FakeContainerService()
    ctx = _ctx("volume", tmp_path)
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        out = UnpackStage(svc, recipe=recipe, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert svc.run_kwargs is None  # no container started on reuse
    assert svc.execs == []  # no container work at all
    assert out.source_root is not None and recipe.src_label in str(out.source_root)
    assert out.srckey == recipe.src_key
    assert any(f"unpack cache hit: {recipe.src_label}" in m for m in msgs)


def test_unpack_applies_patches_then_mrproper_then_chmod_in_order(tmp_path):
    _write_patch(tmp_path, "patches", "b.patch")
    _write_patch(tmp_path, "patches", "a.diff")
    _write_patch(tmp_path, "patches", "ignored.txt")  # non-patch file: must NOT be applied
    recipe = _recipe(patch_hashes=(("patches", "deadbeef"),))
    svc = FakeContainerService()
    ctx = _ctx("volume", tmp_path)

    loc = cache.locations(
        recipe.label,
        arch=recipe.arch,
        storage_mode="volume",
        workspace=tmp_path,
        volume="likedbg_ksrc",
        src_label=recipe.src_label,
    )
    source_root = loc.source_root

    UnpackStage(
        svc,
        recipe=recipe,
        kernel_volume="likedbg_ksrc",
        workspace=tmp_path,
        patch_dirs=("patches",),
    ).run(ctx)

    execs = svc.execs
    rm_idx = next(i for i, c in enumerate(execs) if c == f"rm -rf {source_root}")
    mkdir_idx = next(i for i, c in enumerate(execs) if c == f"mkdir -p {source_root}")
    tar_idx = next(i for i, c in enumerate(execs) if c.startswith("tar ") and source_root in c)
    patch_idxs = [i for i, c in enumerate(execs) if c.startswith("patch -p1 -i ")]
    mrproper_idx = next(i for i, c in enumerate(execs) if "mrproper" in c and f"-C {source_root}" in c)
    chmod_idx = next(i for i, c in enumerate(execs) if c == f"chmod -R a-w {source_root}")

    assert len(patch_idxs) == 2  # only the .patch and .diff files, not .txt
    # a.diff sorts before b.patch
    assert "a.diff" in execs[patch_idxs[0]]
    assert "b.patch" in execs[patch_idxs[1]]
    assert not any("ignored.txt" in c for c in execs)
    # rm -rf (retry atomicity) precedes mkdir -p, then the rest of the pipeline in order.
    assert rm_idx < mkdir_idx < tar_idx < patch_idxs[0] < patch_idxs[1] < mrproper_idx < chmod_idx
    # volume mode: no chown should be issued at all.
    assert not any(c.startswith("chown ") for c in execs)

    # source manifest written AFTER the container work, with patch inputs recorded
    assert manifest_exists(tmp_path, "source", recipe.src_label)
    m = load_manifest(tmp_path, "source", recipe.src_label)
    assert m.key == recipe.src_key
    assert m.version == recipe.version
    assert m.inputs == {"patch:patches": "deadbeef"}


def test_bind_mode_chowns_to_user_after_mrproper_before_chmod(tmp_path):
    recipe = _recipe()
    svc = FakeContainerService()
    ctx = _ctx("bind", tmp_path)

    loc = cache.locations(
        recipe.label,
        arch=recipe.arch,
        storage_mode="bind",
        workspace=tmp_path,
        volume="likedbg_ksrc",
        src_label=recipe.src_label,
    )
    source_root = loc.source_root

    UnpackStage(
        svc,
        recipe=recipe,
        kernel_volume="likedbg_ksrc",
        workspace=tmp_path,
        chown_to=(1000, 1000),
    ).run(ctx)

    execs = svc.execs
    mrproper_idx = next(i for i, c in enumerate(execs) if "mrproper" in c and f"-C {source_root}" in c)
    chown_idx = next(i for i, c in enumerate(execs) if c == f"chown -R 1000:1000 {source_root}")
    chmod_idx = next(i for i, c in enumerate(execs) if c == f"chmod -R a-w {source_root}")

    assert mrproper_idx < chown_idx < chmod_idx


def test_volume_mode_never_chowns_even_with_chown_to_set(tmp_path):
    recipe = _recipe()
    svc = FakeContainerService()
    ctx = _ctx("volume", tmp_path)

    UnpackStage(
        svc,
        recipe=recipe,
        kernel_volume="likedbg_ksrc",
        workspace=tmp_path,
        chown_to=(1000, 1000),
    ).run(ctx)

    assert not any(c.startswith("chown ") for c in svc.execs)


def test_bind_mode_mounts_host_ksrc_dir(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, recipe=_recipe(), kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in mounts
    assert "likedbg_ksrc" not in mounts
    assert (tmp_path / "artifacts" / "ksrc").is_dir()  # bind source created


def test_bind_mode_creates_host_side_src_parent_dir(tmp_path):
    """Regression: the src/ PARENT must be created host-side (as the invoking user), not by the
    root-run container (which only mkdir -p's the leaf source_root). Otherwise the parent ends up
    root-owned and a later host-side `cache.remove_source` rmtree fails with PermissionError on
    the final rmdir. FakeContainerService touches no filesystem, so this dir existing after run()
    proves the stage itself created it, not the (mocked) container."""
    svc = FakeContainerService()
    UnpackStage(svc, recipe=_recipe(), kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    assert (tmp_path / "artifacts" / "ksrc" / "src").is_dir()
