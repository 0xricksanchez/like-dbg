from pathlib import Path

from likedbg.config import Settings
from likedbg.foreign import ForeignKernel
from likedbg.pipeline import PipelineContext
from likedbg.stages.foreign import ForeignAdoptStage
from likedbg.stages.foreign import ForeignRepackStage


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


def test_foreign_adopt_sets_net_fields_on_ctx(tmp_path):
    fk = _fk(tmp_path)
    stage = ForeignAdoptStage(foreign=fk, qemu_extra=(), foreign_net=True, foreign_net_iface="enp0s3")
    ctx = PipelineContext(settings=Settings(), host=_host())
    stage.run(ctx)
    assert ctx.foreign_net is True and ctx.foreign_net_iface == "enp0s3"


class _RepackFakeContainer:
    def __init__(self, out: Path):
        self.execs = []
        self.run_kwargs = None
        self._out = out

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        self._out.parent.mkdir(parents=True, exist_ok=True)
        self._out.write_bytes(b"\x1f\x8b")
        return type("R", (), {"exit_code": 0, "output": ""})()

    def stop(self, container):
        pass


def test_foreign_repack_skips_without_exploit(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    stage = ForeignRepackStage(
        _RepackFakeContainer(tmp_path / "x"),
        foreign=_fk(tmp_path),
        exploit=None,
        image="like_musl:latest",
        out_dir=tmp_path / "stage",
        workspace=tmp_path,
    )
    assert stage.should_skip(ctx) is True


def test_foreign_repack_warns_when_exploit_set_but_no_initramfs(tmp_path, monkeypatch):
    from likedbg.stages import foreign as foreign_mod

    warnings: list[str] = []
    monkeypatch.setattr(foreign_mod.logger, "warning", lambda msg: warnings.append(msg))

    ctx = PipelineContext(settings=Settings(), host=_host())
    fk = ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=None,
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )
    exploit = tmp_path / "exploit.c"
    exploit.write_text("int main(){}\n")
    stage = ForeignRepackStage(
        _RepackFakeContainer(tmp_path / "x"),
        foreign=fk,
        exploit=exploit,
        image="like_musl:latest",
        out_dir=tmp_path / "stage",
        workspace=tmp_path,
    )
    assert stage.should_skip(ctx) is True
    assert len(warnings) == 1
    assert "initramfs" in warnings[0]


def test_foreign_repack_repoints_rootfs(tmp_path):
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "exploit.c"
    exploit.write_text("int main(){}\n")
    out = tmp_path / "stage" / "initramfs.repacked.cpio.gz"
    c = _RepackFakeContainer(out)
    ctx = PipelineContext(settings=Settings(), host=_host())
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).run(ctx)  # sets rootfs to the raw initramfs
    stage = ForeignRepackStage(
        c,
        foreign=_fk(tmp_path),
        exploit=exploit,
        image="like_musl:latest",
        out_dir=tmp_path / "stage",
        workspace=tmp_path,
    )
    assert stage.should_skip(ctx) is False
    stage.run(ctx)
    assert ctx.rootfs_image == out
    assert "x86_64-linux-musl-gcc -static" in " ".join(c.execs)
