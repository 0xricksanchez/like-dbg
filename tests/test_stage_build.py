from pathlib import Path
from types import SimpleNamespace

from loguru import logger

from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import manifest_exists
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.build import BuildStage
from likedbg.stages.build import make_command

# ---------------------------------------------------------------------------
# Shared recipe helper
# ---------------------------------------------------------------------------


def _recipe(fragments=("configs/fragments/debug.config",)):
    return BuildRecipe(
        version="6.6.30",
        arch="arm64",
        compiler="clang",
        make_vars=(("ARCH", "arm64"), ("LLVM", "1")),
        frag_hashes=(),
        fragments=tuple(fragments),
    )


# ---------------------------------------------------------------------------
# FakeC — records execs as (cmd, workdir) tuples; used by existing tests
# ---------------------------------------------------------------------------


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[tuple[str, str | None]] = []
        self.run_kwargs: dict | None = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append((cmd, workdir))
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


# ---------------------------------------------------------------------------
# _ctx for existing tests — takes tmp_path for workspace; sets build_label
# ---------------------------------------------------------------------------


def _ctx(tmp_path: Path, arch: str = "arm64", compiler: str = "clang", storage: str = "volume") -> PipelineContext:
    s = Settings.model_validate({"general": {"arch": arch}, "kernel_builder": {"compiler": compiler}})
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=storage,
        gdbstub_addr="localhost",
        ssh_addr="localhost",
    )
    ctx = PipelineContext(settings=s, host=host)
    ctx.build_label = "linux-6.6.30-a1b2c3d4"
    ctx.kernel_root = None
    return ctx


def _stage(c, tmp_path: Path, fragments=None):
    return BuildStage(
        c,
        recipe=_recipe(fragments or ["configs/fragments/debug.config"]),
        kbuilder_image="like_kbuilder_arm64",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    )


# ---------------------------------------------------------------------------
# _BuildFakeC — records execs as flat strings; has .started flag
# (mirrors Task 5's FakeContainerService pattern)
# ---------------------------------------------------------------------------


class _BuildFakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []
        self.run_kwargs: dict | None = None
        self.started: bool = False

    def run_detached(self, image, **kwargs):
        self.started = True
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


# ---------------------------------------------------------------------------
# make_command unit test (unchanged)
# ---------------------------------------------------------------------------


def test_make_command_includes_arch_llvm_and_nproc():
    cmd = make_command({"ARCH": "arm64", "LLVM": "1"}, "all")
    assert "ARCH=arm64" in cmd and "LLVM=1" in cmd and "-j$(nproc)" in cmd and cmd.endswith("all")


# ---------------------------------------------------------------------------
# Existing behavioral tests — updated to new recipe-based constructor
# ---------------------------------------------------------------------------


def test_build_runs_defconfig_merge_and_make(tmp_path):
    c = FakeC()
    _stage(c, tmp_path, ["configs/fragments/debug.config"]).run(_ctx(tmp_path))
    joined = "\n".join(cmd for cmd, _ in c.execs)
    assert "defconfig" in joined
    assert "merge_config.sh" in joined
    assert "make" in joined and "all" in joined


def test_build_sequence_includes_mrproper(tmp_path):
    """Build sequence must issue mrproper before defconfig and all."""
    c = FakeC()
    _stage(c, tmp_path, ["configs/fragments/debug.config"]).run(_ctx(tmp_path))
    cmds = [cmd for cmd, _ in c.execs]
    joined = "\n".join(cmds)
    assert "mrproper" in joined, "mrproper command not found in build sequence"
    assert "defconfig" in joined
    assert "all" in joined
    # mrproper must come before defconfig
    mrproper_idx = next(i for i, cmd in enumerate(cmds) if "mrproper" in cmd)
    defconfig_idx = next(i for i, cmd in enumerate(cmds) if "defconfig" in cmd and "old" not in cmd)
    assert mrproper_idx < defconfig_idx, "mrproper must run before defconfig"


def test_build_sets_vmlinux_and_image_paths(tmp_path):
    label = "linux-6.6.30-a1b2c3d4"
    out = _stage(FakeC(), tmp_path).run(_ctx(tmp_path, storage="volume"))
    assert out.vmlinux == Path(f"/ksrc/{label}/vmlinux")
    assert out.kernel_image == Path(f"/ksrc/{label}/arch/arm64/boot/Image")


def test_build_volume_mode_mounts_named_volume_and_workspace(tmp_path):
    c = FakeC()
    _stage(c, tmp_path).run(_ctx(tmp_path, storage="volume"))
    vols = str(c.run_kwargs["volumes"])
    assert "likedbg_ksrc" in vols and str(tmp_path) in vols


# ---------------------------------------------------------------------------
# New cache-aware tests
# ---------------------------------------------------------------------------


def test_build_reuses_when_manifest_present(tmp_path):
    label = "linux-6.6.30-a1b2c3d4"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={
                "vmlinux_in_tree": f"/ksrc/{label}/vmlinux",
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
            },
        ),
    )
    c = _BuildFakeC()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        out = BuildStage(
            c,
            recipe=_recipe(),
            kbuilder_image="like_kbuilder_arm64:latest",
            workspace=tmp_path,
            kernel_volume="likedbg_ksrc",
        ).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert str(out.vmlinux) == f"/ksrc/{label}/vmlinux"
    assert str(out.kernel_image) == f"/ksrc/{label}/arch/arm64/boot/Image"
    assert c.started is False
    assert any(f"build cache hit: {label}" in m for m in msgs)


def test_build_reuses_bind_manifest_uses_host_image(tmp_path):
    label = "linux-6.6.30-a1b2c3d4"
    image_host = str(tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot" / "Image")
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="bind",
            paths={
                "vmlinux_in_tree": f"/ksrc/{label}/vmlinux",
                "image_host": image_host,
            },
        ),
    )
    c = _BuildFakeC()
    ctx = _ctx(tmp_path, storage="bind")
    ctx.build_label = label
    ctx.kernel_root = None
    out = BuildStage(
        c,
        recipe=_recipe(),
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    assert c.started is False  # cache hit, no container started
    assert str(out.kernel_image) == image_host  # bind cached path uses image_host, not image_in_tree


def test_build_bind_mode_mounts_host_ksrc_and_chowns(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    ctx = _ctx(tmp_path, storage="bind")
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=_recipe(),
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        chown_to=(1000, 1000),
    ).run(ctx)
    vols = str(c.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in vols and "likedbg_ksrc" not in vols
    assert any(f"chown -R 1000:1000 /ksrc/{label}" in e for e in c.execs)
    # in bind, the in-container QEMU needs the HOST image path
    assert str(ctx.kernel_image) == str(tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot" / "Image")


def test_build_volume_mode_does_not_chown(tmp_path):
    c = _BuildFakeC()
    ctx = _ctx(tmp_path, storage="volume")
    ctx.build_label = "linux-6.6.30-a1b2c3d4"
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=_recipe(),
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        chown_to=(1000, 1000),
    ).run(ctx)
    assert all("chown" not in e for e in c.execs)  # chown is bind-only


def test_build_compiles_with_recipe_make_vars_then_writes_manifest(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=_recipe(),
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    allcmds = " ; ".join(c.execs)
    assert "ARCH=arm64" in allcmds and "LLVM=1" in allcmds  # from the recipe, not settings
    assert "make" in allcmds and "all" in allcmds
    assert manifest_exists(tmp_path, "build", label) is True
