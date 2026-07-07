from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from likedbg.errors import LikeDbgError
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import detect_arch


def _elf_header(e_machine: bytes) -> bytes:
    # e_ident(16) = magic(4) + class(1)=64bit + data(1)=LE + version(1) + osabi/pad(9);
    # e_type(2) at 16; e_machine(2) at 18 (little-endian).
    e_ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    return e_ident + b"\x02\x00" + e_machine + b"\x00" * 20


def test_detect_arch_x86_64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x3e\x00"))  # EM_X86_64 = 62
    assert detect_arch(v) == "x86_64"


def test_detect_arch_aarch64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\xb7\x00"))  # EM_AARCH64 = 183
    assert detect_arch(v) == "arm64"


def test_detect_arch_non_elf_raises(tmp_path: Path) -> None:
    v = tmp_path / "notelf"
    v.write_bytes(b"MZ\x90\x00not an elf")
    with pytest.raises(ForeignError, match="not an ELF"):
        detect_arch(v)


def test_detect_arch_unknown_machine_raises(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x28\x00"))  # EM_ARM (32-bit) = 40, unsupported
    with pytest.raises(ForeignError, match="e_machine"):
        detect_arch(v)


def test_detect_arch_truncated_header_raises(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(b"\x7fELF")  # magic only, header cut off before e_machine
    with pytest.raises(ForeignError, match="(?i)truncated|too short"):
        detect_arch(v)


def test_foreign_error_is_likedbg_error() -> None:
    assert issubclass(ForeignError, LikeDbgError)


def test_foreign_kernel_is_frozen(tmp_path: Path) -> None:
    fk = ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet",
    )
    with pytest.raises(FrozenInstanceError):
        fk.arch = "arm64"  # type: ignore[misc]


class _FakeContainer:
    def __init__(self, *, make_out: Path | None = None, out_bytes: bytes = b"\x7fELF") -> None:
        self.run_kwargs: dict | None = None
        self.execs: list[str] = []
        self.stopped = False
        self._make_out = make_out
        self._out_bytes = out_bytes

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if self._make_out is not None:  # simulate the container writing the output file
            self._make_out.write_bytes(self._out_bytes)
        return type("R", (), {"exit_code": 0, "output": ""})()

    def stop(self, container):
        self.stopped = True


def test_extract_vmlinux_runs_script_and_returns_out(tmp_path: Path) -> None:
    from likedbg.foreign import extract_vmlinux

    image_path = tmp_path / "in" / "bzImage"
    image_path.parent.mkdir()
    image_path.write_bytes(b"MZfake-bzImage")
    out = tmp_path / "out" / "vmlinux"
    c = _FakeContainer(make_out=out)

    result = extract_vmlinux(c, image_path, out, image="like_musl:latest")

    assert result == out and out.is_file()
    assert c.run_kwargs["image"] == "like_musl:latest"
    vols = c.run_kwargs["volumes"]
    assert vols[str(image_path.parent)] == {"bind": "/in", "mode": "ro"}
    assert vols[str(out.parent)] == {"bind": "/out", "mode": "rw"}
    assert "/opt/extract-vmlinux.sh /in/bzImage /out/vmlinux" in " ".join(c.execs)
    assert c.stopped is True


def test_extract_vmlinux_missing_output_raises(tmp_path: Path) -> None:
    from likedbg.foreign import extract_vmlinux

    image_path = tmp_path / "in" / "Image"
    image_path.parent.mkdir()
    image_path.write_bytes(b"arm64-Image")
    out = tmp_path / "out" / "vmlinux"
    c = _FakeContainer(make_out=None)  # container "produces" nothing
    with pytest.raises(ForeignError, match="could not extract vmlinux"):
        extract_vmlinux(c, image_path, out, image="like_musl:latest")


def test_resolve_input_path_absolute_and_relative(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_input_path

    assert resolve_input_path(tmp_path, "/abs/x") == Path("/abs/x")
    assert resolve_input_path(tmp_path, "ctf/lk01/bzImage") == tmp_path / "ctf/lk01/bzImage"


def _mk_cfg(**kw):
    from likedbg.config import ForeignCfg

    return ForeignCfg(**kw)


def test_resolve_foreign_uses_provided_vmlinux_and_detects_arch(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(_elf_header(b"\x3e\x00"))  # x86_64
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    cfg = _mk_cfg(image="bzImage", vmlinux="vmlinux", initramfs="initramfs.cpio.gz", cmdline="quiet")
    c = _FakeContainer(make_out=None)

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")

    assert fk.arch == "x86_64"
    assert fk.image == tmp_path / "bzImage"
    assert fk.vmlinux == tmp_path / "vmlinux"
    assert fk.initramfs == tmp_path / "initramfs.cpio.gz"
    assert fk.cmdline == "quiet"
    assert c.run_kwargs is None  # no extraction when vmlinux provided


def test_resolve_foreign_extracts_vmlinux_when_absent(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "bzImage").write_bytes(b"MZ")
    staged = tmp_path / "stage" / "vmlinux"
    c = _FakeContainer(make_out=staged, out_bytes=_elf_header(b"\x3e\x00"))
    cfg = _mk_cfg(image="bzImage", cmdline="quiet")

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")

    assert fk.vmlinux == staged and fk.arch == "x86_64"
    assert c.run_kwargs is not None  # extraction ran


def test_resolve_foreign_arch_override_skips_detection(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "Image").write_bytes(b"arm64-Image")
    (tmp_path / "vmlinux").write_bytes(b"not-an-elf")  # would fail detect_arch
    cfg = _mk_cfg(image="Image", vmlinux="vmlinux", arch="arm64", cmdline="")
    c = _FakeContainer(make_out=None)

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")
    assert fk.arch == "arm64"


def test_resolve_foreign_missing_image_raises(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    cfg = _mk_cfg(image="nope/bzImage")
    c = _FakeContainer(make_out=None)
    with pytest.raises(ForeignError, match="image"):
        resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")


def test_repack_initramfs_compiles_c_with_cross_musl(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "initramfs.cpio.gz"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "src" / "exploit.c"
    exploit.parent.mkdir()
    exploit.write_text("int main(){return 0;}\n")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    result = repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest")

    assert result == out
    cmd = " ".join(c.execs)
    assert "x86_64-linux-musl-gcc -static /src/exploit.c -o" in cmd
    assert "cpio --null --format=newc -o" in cmd and "gzip" in cmd
    vols = c.run_kwargs["volumes"]
    assert vols[str(initramfs.parent)]["mode"] == "ro"
    assert vols[str(out.parent)]["mode"] == "rw"


def test_repack_initramfs_arm64_uses_aarch64_gcc(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "rootfs.cpio"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"07070100")  # newc magic
    exploit = tmp_path / "src" / "pwn.c"
    exploit.parent.mkdir()
    exploit.write_text("int main(){}\n")
    out = tmp_path / "out" / "repacked.cpio"
    c = _FakeContainer(make_out=out, out_bytes=b"07070100")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="arm64", out=out, image="like_musl:latest")
    assert "aarch64-linux-musl-gcc -static" in " ".join(c.execs)


def test_repack_initramfs_copies_prebuilt_binary(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "initramfs.cpio.gz"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "src" / "exploit"  # no .c suffix = prebuilt static binary
    exploit.parent.mkdir()
    exploit.write_bytes(b"\x7fELFstatic")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest")
    cmd = " ".join(c.execs)
    assert "cp /src/exploit" in cmd and "musl-gcc" not in cmd
