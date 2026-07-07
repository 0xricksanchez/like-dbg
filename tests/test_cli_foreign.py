from likedbg.cli import build_foreign_pipeline
from likedbg.container_service import ContainerService
from likedbg.foreign import ForeignKernel
from likedbg.host_profile import HostProfile


def _host(mode="in-container", target_arch="x86_64"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=target_arch,
        accel="tcg",
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


class _FakeSession:
    def __init__(self):
        self.options = {}
        self._panes = iter(["%2", "%3"])

    def current_pane_id(self):
        return "%1"

    def unset_option(self, k):
        pass

    def set_option(self, k, v):
        self.options[k] = v

    def run_in_new_pane(self, *, target, direction, percent, cmd):
        return next(self._panes)

    def pipe_pane(self, *, pane, output):
        pass


class _FakeContainer(ContainerService):
    def __init__(self):
        pass


def _fk(tmp_path):
    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(b"\x7fELF")
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    return ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )


def test_build_foreign_pipeline_stage_order(tmp_path):
    pipe = build_foreign_pipeline(
        _FakeContainer(),
        _FakeSession(),  # type: ignore[arg-type]
        host=_host(),
        workspace=tmp_path,
        foreign=_fk(tmp_path),
        exploit=None,
        qemu_extra=(),
        gdb_mount_source=str(tmp_path),
        out_dir=tmp_path / "stage",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        musl_image="like_musl:latest",
        recorder=None,
    )
    assert [s.name for s in pipe._stages] == [  # type: ignore[attr-defined]
        "foreign-adopt",
        "foreign-repack",
        "debuggee",
        "debugger",
    ]
