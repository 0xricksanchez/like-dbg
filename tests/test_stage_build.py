from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.build import BuildStage
from likedbg.stages.build import make_command


class FakeC(ContainerService):
    def __init__(self):
        self.execs = []
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append((cmd, workdir))
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(arch="arm64", compiler="clang", storage="bind"):
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
    ctx.kernel_root = Path("/ksrc/linux-6.6" if storage == "volume" else "/io/linux-6.6")
    return ctx


def _stage(c, fragments=None):
    return BuildStage(
        c,
        kbuilder_image="like_kbuilder_arm64",
        fragments=fragments or [],
        workspace=Path("/repo"),
        kernel_volume="likedbg_ksrc",
    )


def test_make_command_includes_arch_llvm_and_nproc():
    cmd = make_command({"ARCH": "arm64", "LLVM": "1"}, "all")
    assert "ARCH=arm64" in cmd and "LLVM=1" in cmd and "-j$(nproc)" in cmd and cmd.endswith("all")


def test_build_runs_defconfig_merge_and_make():
    c = FakeC()
    _stage(c, ["configs/fragments/debug.config"]).run(_ctx())
    joined = "\n".join(cmd for cmd, _ in c.execs)
    assert "defconfig" in joined
    assert "merge_config.sh" in joined
    assert "make" in joined and "all" in joined


def test_build_sequence_includes_mrproper(tmp_path):
    """Build sequence must issue mrproper before defconfig and all."""
    c = FakeC()
    _stage(c, ["configs/fragments/debug.config"]).run(_ctx())
    cmds = [cmd for cmd, _ in c.execs]
    joined = "\n".join(cmds)
    assert "mrproper" in joined, "mrproper command not found in build sequence"
    assert "defconfig" in joined
    assert "all" in joined
    # mrproper must come before defconfig
    mrproper_idx = next(i for i, cmd in enumerate(cmds) if "mrproper" in cmd)
    defconfig_idx = next(i for i, cmd in enumerate(cmds) if "defconfig" in cmd and "old" not in cmd)
    assert mrproper_idx < defconfig_idx, "mrproper must run before defconfig"


def test_build_sets_vmlinux_and_image_paths():
    out = _stage(FakeC()).run(_ctx("arm64"))
    assert out.vmlinux == Path("/io/linux-6.6/vmlinux")
    assert out.kernel_image == Path("/io/linux-6.6/arch/arm64/boot/Image")


def test_build_volume_mode_mounts_named_volume_and_workspace():
    c = FakeC()
    _stage(c).run(_ctx(storage="volume"))
    vols = str(c.run_kwargs["volumes"])
    assert "likedbg_ksrc" in vols and "/repo" in vols
