from pathlib import Path

from likedbg.config import Settings
from likedbg.foreign import ForeignKernel
from likedbg.pipeline import PipelineContext
from likedbg.stages.foreign import ForeignAdoptStage


class _Rec:
    def __init__(self):
        self.kernel_paths = None

    def record_kernel_paths(self, *, config, system_map, vmlinux, image):
        self.kernel_paths = {"config": config, "system_map": system_map, "vmlinux": vmlinux, "image": image}


def _host(target_arch="x86_64"):
    from likedbg.host_profile import HostProfile

    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=target_arch,
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


def _fk(tmp_path):
    return ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )


def test_foreign_adopt_sets_ctx_fields(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=("-no-reboot",)).run(ctx)
    assert ctx.kernel_image == tmp_path / "bzImage"
    assert ctx.rootfs_image == tmp_path / "initramfs.cpio.gz"
    assert ctx.vmlinux == Path("/ksrc/vmlinux")  # in-container gdb path
    assert ctx.foreign_cmdline == "quiet console=ttyS0"
    assert ctx.qemu_extra == ("-no-reboot",)


def test_foreign_adopt_records_kernel_paths_config_none(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    rec = _Rec()
    ctx.recorder = rec
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).run(ctx)
    assert rec.kernel_paths["config"] is None
    assert rec.kernel_paths["vmlinux"] == str(tmp_path / "vmlinux")
    assert rec.kernel_paths["image"] == str(tmp_path / "bzImage")


def test_foreign_adopt_does_not_skip(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    assert ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).should_skip(ctx) is False
