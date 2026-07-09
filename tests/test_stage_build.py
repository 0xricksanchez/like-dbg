from pathlib import Path
from types import SimpleNamespace

from loguru import logger

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.cache import Manifest
from likedbg.cache import load_manifest
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


def _loc(tmp_path: Path, recipe: BuildRecipe, label: str, storage: str = "volume"):
    return cache.locations(
        label,
        arch=recipe.arch,
        storage_mode=storage,
        workspace=tmp_path,
        volume="likedbg_ksrc",
        src_label=recipe.src_label,
    )


# ---------------------------------------------------------------------------
# FakeC — records execs as (cmd, workdir) tuples; used by existing tests
# ---------------------------------------------------------------------------


_DU_OUTPUT = "12345\t/ksrc/obj/fake\n"


def _fake_exec_output(cmd: str) -> str:
    """Shared canned response used by every fake container's exec(): answers `du -sb` (needed
    since BuildStage now parses its output for size_bytes) and "" for everything else, so the
    rest of the (unrelated) build flow is unaffected."""
    return _DU_OUTPUT if cmd.startswith("du -sb") else ""


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[tuple[str, str | None]] = []
        self.run_kwargs: dict | None = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append((cmd, workdir))
        return SimpleNamespace(exit_code=0, output=_fake_exec_output(cmd))

    def stop(self, container):
        pass


# ---------------------------------------------------------------------------
# _ctx for existing tests — takes tmp_path for workspace; sets build_label
# ---------------------------------------------------------------------------


def _ctx(tmp_path: Path, arch: str = "arm64", compiler: str = "clang", storage: str = "volume") -> PipelineContext:
    s = Settings.model_validate({"general": {"arch": arch}, "build": {"compiler": compiler}})
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=storage,
        gdbstub_addr="localhost",
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
        return SimpleNamespace(exit_code=0, output=_fake_exec_output(cmd))

    def stop(self, container):
        pass


# ---------------------------------------------------------------------------
# make_command unit tests
# ---------------------------------------------------------------------------


def test_make_command_includes_arch_llvm_and_nproc():
    cmd = make_command({"ARCH": "arm64", "LLVM": "1"}, "all")
    assert "ARCH=arm64" in cmd and "LLVM=1" in cmd and "-j$(nproc)" in cmd and cmd.endswith("all")


def test_make_command_out_of_tree_includes_dash_c_and_o():
    cmd = make_command(
        {"ARCH": "arm64"}, "defconfig", source_root="/ksrc/src/linux-x", objdir="/ksrc/obj/linux-y"
    )
    assert "-C /ksrc/src/linux-x" in cmd
    assert "O=/ksrc/obj/linux-y" in cmd
    assert cmd.endswith("defconfig")


# ---------------------------------------------------------------------------
# Existing behavioral tests — updated to new recipe-based constructor
# ---------------------------------------------------------------------------


def test_build_runs_defconfig_merge_and_make_out_of_tree(tmp_path):
    c = FakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe(["configs/fragments/debug.config"])
    loc = _loc(tmp_path, recipe, label)
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(_ctx(tmp_path))
    joined = "\n".join(cmd for cmd, _ in c.execs)
    assert f"-C {loc.source_root} O={loc.objdir}" in joined
    assert "defconfig" in joined
    assert f"merge_config.sh -m -O {loc.objdir} {loc.objdir}/.config" in joined
    assert "olddefconfig" in joined
    assert "make" in joined and joined.count(" all") >= 1
    assert f"O={loc.objdir}" in joined


def test_build_sequence_has_no_mrproper_and_no_patch_application(tmp_path):
    """mrproper and patch application both moved to UnpackStage; BuildStage must not re-issue them."""
    c = FakeC()
    _stage(c, tmp_path, ["configs/fragments/debug.config"]).run(_ctx(tmp_path))
    cmds = [cmd for cmd, _ in c.execs]
    joined = "\n".join(cmds)
    assert "mrproper" not in joined
    assert "patch -p1" not in joined
    assert "defconfig" in joined
    assert " all" in joined


def test_build_sets_vmlinux_and_image_paths(tmp_path):
    label = "linux-6.6.30-a1b2c3d4"
    out = _stage(FakeC(), tmp_path).run(_ctx(tmp_path, storage="volume"))
    assert out.vmlinux == Path(f"/ksrc/obj/{label}/vmlinux")
    assert out.kernel_image == Path(f"/ksrc/obj/{label}/arch/arm64/boot/Image")
    assert out.objdir == Path(f"/ksrc/obj/{label}")
    assert out.kernel_root == Path(f"/ksrc/obj/{label}")  # deprecated alias, kept for compat


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
    assert out.objdir == Path(f"/ksrc/obj/{label}")  # objdir set even on cache hit
    assert c.started is False
    assert any(f"build cache hit: {label}" in m for m in msgs)
    assert out.build_was_cached is True  # CacheEvictionStage skips: a cache hit adds no disk


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


def test_build_bind_mode_mounts_host_ksrc_and_chowns_objdir(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    ctx = _ctx(tmp_path, storage="bind")
    ctx.build_label = label
    ctx.kernel_root = None
    loc = _loc(tmp_path, recipe, label, storage="bind")
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        chown_to=(1000, 1000),
    ).run(ctx)
    vols = str(c.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in vols and "likedbg_ksrc" not in vols
    # chown must target the objdir, NOT the flat /ksrc/<label> (carried defect fixed)
    assert any(f"chown -R 1000:1000 {loc.objdir}" in e for e in c.execs)
    assert not any(f"chown -R 1000:1000 /ksrc/{label}" == e for e in c.execs)
    assert not any(e.endswith(f"chown -R 1000:1000 /ksrc/{label}") for e in c.execs)
    # in bind, the in-container QEMU needs the HOST image path
    assert str(ctx.kernel_image) == str(
        tmp_path / "artifacts" / "ksrc" / "obj" / label / "arch" / "arm64" / "boot" / "Image"
    )


def test_build_bind_mode_creates_host_side_obj_parent_dir(tmp_path):
    """Regression: the obj/ PARENT must be created host-side (as the invoking user), not by the
    root-run container (which only mkdir -p's the leaf objdir). Otherwise the parent ends up
    root-owned and a later host-side `cache.remove_cached` rmtree fails with PermissionError on
    the final rmdir. _BuildFakeC touches no filesystem, so this dir existing after run() proves
    the stage itself created it, not the (mocked) container."""
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    ctx = _ctx(tmp_path, storage="bind")
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    assert (tmp_path / "artifacts" / "ksrc" / "obj").is_dir()


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


def test_build_compiles_with_recipe_make_vars_then_writes_manifest_with_srckey_and_objdir(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    loc = _loc(tmp_path, recipe, label)
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    allcmds = " ; ".join(c.execs)
    assert "ARCH=arm64" in allcmds and "LLVM=1" in allcmds  # from the recipe, not settings
    assert "make" in allcmds and " all" in allcmds
    assert manifest_exists(tmp_path, "build", label) is True
    m = load_manifest(tmp_path, "build", label)
    assert m.srckey == recipe.src_key
    assert m.paths["objdir"] == loc.objdir
    assert m.paths["source_root"] == loc.source_root
    assert ctx.build_was_cached is False  # fresh build: CacheEvictionStage may run


def test_build_stamps_size_bytes_and_last_used_from_du(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    loc = _loc(tmp_path, recipe, label)
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    assert any(cmd == f"du -sb {loc.objdir}" for cmd in c.execs)
    m = load_manifest(tmp_path, "build", label)
    assert m.size_bytes == 12345
    assert m.last_used != ""


def test_build_config_snapshot_read_from_objdir_dot_config(tmp_path):
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    loc = _loc(tmp_path, recipe, label)

    class _ConfigFakeC(_BuildFakeC):
        def exec(self, container, cmd, *, workdir=None):
            self.execs.append(cmd)
            if cmd == f"cat {loc.objdir}/.config":
                return SimpleNamespace(exit_code=0, output="CONFIG_FOO=y\r\n")
            return SimpleNamespace(exit_code=0, output=_fake_exec_output(cmd))

    c = _ConfigFakeC()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    assert any(cmd == f"cat {loc.objdir}/.config" for cmd in c.execs)
    config_host = tmp_path / "artifacts" / label / "config"
    assert config_host.read_text() == "CONFIG_FOO=y\n"  # CRLF stripped


def test_build_ccache_enabled_mounts_volume_and_wires_env(tmp_path):
    from likedbg.constants import LIKEDBG_CCACHE_VOLUME

    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        ccache=True,
        ccache_max_size="5G",
    ).run(ctx)
    vols = c.run_kwargs["volumes"]
    assert vols[LIKEDBG_CCACHE_VOLUME] == {"bind": "/ccache", "mode": "rw"}
    compile_cmds = [cmd for cmd in c.execs if " all" in cmd]
    assert compile_cmds, "expected a compile (all target) command to be issued"
    joined = " ; ".join(compile_cmds)
    assert "CCACHE_DIR=/ccache" in joined
    assert "CCACHE_NOHASHDIR=1" in joined
    assert "CCACHE_MAXSIZE=5G" in joined
    assert 'CC="ccache clang"' in joined
    assert "-fdebug-prefix-map" not in joined
    assert "-ffile-prefix-map" not in joined


def test_build_ccache_disabled_by_default_no_volume_no_env(tmp_path):
    from likedbg.constants import LIKEDBG_CCACHE_VOLUME

    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    vols = c.run_kwargs["volumes"]
    assert LIKEDBG_CCACHE_VOLUME not in vols
    allcmds = " ; ".join(c.execs)
    assert "CCACHE_DIR" not in allcmds
    assert "CCACHE_NOHASHDIR" not in allcmds
    assert "CCACHE_MAXSIZE" not in allcmds
    assert "ccache" not in allcmds


def test_build_ccache_with_gcc_no_cc_wrap_clang_still_wrapped(tmp_path):
    """gcc ccache wiring deferred; clang wrap must still be applied."""
    from likedbg.constants import LIKEDBG_CCACHE_VOLUME

    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    gcc_recipe = BuildRecipe(
        version="6.6.30",
        arch="arm64",
        compiler="gcc",
        make_vars=(("ARCH", "arm64"), ("CROSS_COMPILE", "aarch64-linux-gnu-")),
        frag_hashes=(),
        fragments=("configs/fragments/debug.config",),
    )
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=gcc_recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        ccache=True,
        ccache_max_size="5G",
    ).run(ctx)
    vols = c.run_kwargs["volumes"]
    assert vols[LIKEDBG_CCACHE_VOLUME] == {"bind": "/ccache", "mode": "rw"}
    compile_cmds = [cmd for cmd in c.execs if " all" in cmd]
    assert compile_cmds, "expected a compile (all target) command to be issued"
    joined = " ; ".join(compile_cmds)
    assert "CCACHE_DIR=/ccache" in joined
    assert "CCACHE_NOHASHDIR=1" in joined
    assert "CCACHE_MAXSIZE=5G" in joined
    assert 'CC="ccache gcc"' not in joined, "gcc should not get CC wrapper; uses CROSS_COMPILE-derived CC"
    # Also verify clang still gets wrapped
    c_clang = _BuildFakeC()
    ctx_clang = _ctx(tmp_path)
    ctx_clang.build_label = "linux-6.6.30-x1y2z3w4"
    ctx_clang.kernel_root = None
    BuildStage(
        c_clang,
        recipe=_recipe(),
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        ccache=True,
        ccache_max_size="5G",
    ).run(ctx_clang)
    compile_cmds_clang = [cmd for cmd in c_clang.execs if " all" in cmd]
    joined_clang = " ; ".join(compile_cmds_clang)
    assert 'CC="ccache clang"' in joined_clang, "clang must get CC wrapper"


def test_build_does_not_apply_patches_patches_moved_to_unpack(tmp_path) -> None:
    """BuildStage no longer applies patches (UnpackStage does); BuildStage's constructor no
    longer accepts patch_dirs at all (dead param removed, Task 8)."""
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    patches = tmp_path / "patches" / "uaf"
    patches.mkdir(parents=True)
    (patches / "0001-a.patch").write_text("p1")
    (patches / "0002-b.patch").write_text("p2")
    from likedbg.cache import build_recipe as _build_recipe

    r = _build_recipe(
        Settings.model_validate({}),
        version="6.6.30",
        arch="x86_64",
        workspace=tmp_path,
        fragments=[frag],
        patch_dirs=("patches/uaf",),
    )
    c = _BuildFakeC()
    ctx = _ctx(tmp_path, arch="arm64")
    ctx.build_label = r.label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=r,
        kbuilder_image="like_kbuilder_x86_64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    patch_cmds = [cmd for cmd in c.execs if "patch -p1" in cmd or "git apply" in cmd]
    assert len(patch_cmds) == 0


def test_build_handles_malformed_du_output_sets_size_zero(tmp_path):
    """Robustness: if du -sb returns empty or unparseable output, size_bytes defaults to 0
    (best-effort accounting) rather than crashing a successful build."""
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()

    class _MalformedDuFakeC(_BuildFakeC):
        def exec(self, container, cmd, *, workdir=None):
            self.execs.append(cmd)
            if cmd.startswith("du -sb"):
                return SimpleNamespace(exit_code=0, output="")  # empty du output
            return SimpleNamespace(exit_code=0, output=_fake_exec_output(cmd))

    c = _MalformedDuFakeC()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    m = load_manifest(tmp_path, "build", label)
    assert m.size_bytes == 0  # defaults to 0, does not raise


def test_build_handles_garbage_du_output_sets_size_zero(tmp_path):
    """Robustness: if du -sb returns garbage (no leading bytes field), size_bytes defaults to 0."""
    label = "linux-6.6.30-a1b2c3d4"
    recipe = _recipe()

    class _GarbageDuFakeC(_BuildFakeC):
        def exec(self, container, cmd, *, workdir=None):
            self.execs.append(cmd)
            if cmd.startswith("du -sb"):
                return SimpleNamespace(exit_code=0, output="not_a_number\t/path\n")
            return SimpleNamespace(exit_code=0, output=_fake_exec_output(cmd))

    c = _GarbageDuFakeC()
    ctx = _ctx(tmp_path)
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c,
        recipe=recipe,
        kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
    ).run(ctx)
    m = load_manifest(tmp_path, "build", label)
    assert m.size_bytes == 0  # defaults to 0, does not raise
