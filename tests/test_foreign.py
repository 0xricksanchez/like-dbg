import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from likedbg.constants import V2E_VERSION
from likedbg.errors import ContainerError
from likedbg.errors import LikeDbgError
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import _image_sha256
from likedbg.foreign import _trust_gate
from likedbg.foreign import detect_arch
from likedbg.foreign import extract_vmlinux


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


def test_compile_exploit_builds_musl_static_command_x86(tmp_path):
    from likedbg.foreign import compile_exploit

    src = tmp_path / "src" / "e.c"
    src.parent.mkdir()
    src.write_text("int main(void){return 0;}\n")
    out = tmp_path / "out" / "e"
    c = _FakeContainer(make_out=out, out_bytes=b"\x7fELFbin")

    result = compile_exploit(c, src=src, arch="x86_64", out=out, image="like_musl:latest")

    assert result == out and out.is_file()
    cmd = " ".join(c.execs)
    assert "x86_64-linux-musl-gcc -static" in cmd and "/src/e.c" in cmd and "/out/e" in cmd
    vols = c.run_kwargs["volumes"]
    assert vols[str(src.parent)]["mode"] == "ro" and vols[str(out.parent)]["mode"] == "rw"


def test_compile_exploit_arm64_uses_aarch64(tmp_path):
    from likedbg.foreign import compile_exploit

    src = tmp_path / "s" / "e.c"
    src.parent.mkdir()
    src.write_text("int main(void){}\n")
    out = tmp_path / "o" / "e"
    c = _FakeContainer(make_out=out, out_bytes=b"\x7fELF")
    compile_exploit(c, src=src, arch="arm64", out=out, image="like_musl:latest")
    assert "aarch64-linux-musl-gcc -static" in " ".join(c.execs)


def test_compile_exploit_missing_output_raises(tmp_path):
    from likedbg.foreign import ForeignError
    from likedbg.foreign import compile_exploit

    src = tmp_path / "s" / "e.c"
    src.parent.mkdir()
    src.write_text("boom\n")
    out = tmp_path / "o" / "e"
    c = _FakeContainer(make_out=None)  # container produces nothing
    with pytest.raises(ForeignError, match="compile"):
        compile_exploit(c, src=src, arch="x86_64", out=out, image="like_musl:latest")


def test_compile_exploit_invalid_arch_raises(tmp_path):
    from likedbg.foreign import ForeignError
    from likedbg.foreign import compile_exploit

    src = tmp_path / "s" / "e.c"
    src.parent.mkdir()
    src.write_text("x\n")
    with pytest.raises(ForeignError, match="arch"):
        compile_exploit(_FakeContainer(make_out=None), src=src, arch="mips", out=tmp_path / "o" / "e", image="m")


def test_compile_exploit_resolves_relative_src_to_absolute_mount(tmp_path, monkeypatch):
    """A relative src path must be resolved to an absolute bind-mount host path — a relative path
    becomes a docker NAMED VOLUME, so /src/<file> would not exist (x86 live-gate bug)."""
    from likedbg.foreign import compile_exploit

    (tmp_path / "exploit").mkdir()
    (tmp_path / "exploit" / "e.c").write_text("int main(void){}\n")
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "run" / "e"
    c = _FakeContainer(make_out=out, out_bytes=b"\x7fELF")
    compile_exploit(c, src=Path("exploit/e.c"), arch="x86_64", out=out, image="like_musl:latest")
    for host_path in c.run_kwargs["volumes"]:
        assert host_path.startswith("/"), f"non-absolute mount host path: {host_path}"
    assert str((tmp_path / "exploit").resolve()) in c.run_kwargs["volumes"]


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


def test_repack_initramfs_quotes_filename_with_space(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "odd name.cpio.gz"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "src" / "exploit.c"
    exploit.parent.mkdir()
    exploit.write_text("int main(){return 0;}\n")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest")
    cmd = " ".join(c.execs)
    assert "'/in/odd name.cpio.gz'" in cmd
    # unquoted form must not appear as a standalone shell token
    assert "/in/odd name.cpio.gz " not in cmd.replace("'/in/odd name.cpio.gz'", "")


def test_repack_initramfs_same_dir_initramfs_and_exploit_shares_one_mount(tmp_path: Path) -> None:
    """Regression: a CTF challenge commonly ships initramfs + exploit.c in the SAME dir.
    Pre-fix, the volumes dict was keyed by parent dir, so the duplicate key collapsed to 2
    mounts and dropped the /in bind entirely (gzip -dc /in/... then fails)."""
    from likedbg.foreign import repack_initramfs

    challenge_dir = tmp_path / "ctf" / "lk01"
    challenge_dir.mkdir(parents=True)
    initramfs = challenge_dir / "initramfs.cpio.gz"
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = challenge_dir / "exploit.c"
    exploit.write_text("int main(){return 0;}\n")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest")

    vols = c.run_kwargs["volumes"]
    binds = {v["bind"] for v in vols.values()}
    assert "/in" in binds  # the /in bind must not be dropped
    assert vols[str(challenge_dir)]["bind"] == "/in"
    assert vols[str(out.parent)] == {"bind": "/out", "mode": "rw"}
    assert len(vols) == 2  # challenge dir shares one mount, out gets its own

    cmd = " ".join(c.execs)
    assert "/in/initramfs.cpio.gz" in cmd  # both files referenced under the shared /in mount
    assert "/in/exploit.c" in cmd


def test_extract_vmlinux_same_dir_image_and_out_shares_one_rw_mount(tmp_path: Path) -> None:
    """Regression: image + out sharing a dir must not drop a mount, and since /out needs rw,
    the single shared mount must be upgraded to rw (not left ro)."""
    from likedbg.foreign import extract_vmlinux

    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    image_path = shared_dir / "bzImage"
    image_path.write_bytes(b"MZfake-bzImage")
    out = shared_dir / "vmlinux"
    c = _FakeContainer(make_out=out)

    extract_vmlinux(c, image_path, out, image="like_musl:latest")

    vols = c.run_kwargs["volumes"]
    assert len(vols) == 1  # single shared mount, no dropped mount
    mount = vols[str(shared_dir)]
    assert mount["mode"] == "rw"  # upgraded because /out needs write access

    cmd = " ".join(c.execs)
    assert f"{mount['bind']}/bzImage" in cmd
    assert f"{mount['bind']}/vmlinux" in cmd


def test_console_upload_probe_failure_says_use_repack(tmp_path):
    from likedbg.foreign import console_upload

    payload = tmp_path / "expl"
    payload.write_bytes(b"\x7fELFsmall")

    class _Sess:
        def __init__(self):
            self.sent = []

        def send_keys(self, pane, keys, *, enter=True):
            self.sent.append(keys)

    sess = _Sess()
    # console read reports base64 missing -> probe fails
    with pytest.raises(ForeignError, match="use repack"):
        console_upload(sess, "%2", payload, read_console=lambda: "LIKEDBG-PROBE base64=no tmp=yes\n")


def test_console_upload_sends_chunks_and_verifies(tmp_path):
    from hashlib import sha256

    from likedbg.foreign import console_upload

    payload = tmp_path / "expl"
    data = b"\x7fELF" + b"A" * 40
    payload.write_bytes(data)
    digest = sha256(data).hexdigest()

    class _Sess:
        def __init__(self):
            self.sent = []

        def send_keys(self, pane, keys, *, enter=True):
            self.sent.append(keys)

    sess = _Sess()
    # probe OK, then the guest echoes matching size + sha256
    reads = iter(
        [
            "LIKEDBG-PROBE base64=yes tmp=yes\n",
            f"LIKEDBG-DONE size={len(data)} sha={digest}\n",
        ]
    )
    console_upload(sess, "%2", payload, read_console=lambda: next(reads))
    joined = "\n".join(sess.sent)
    assert "base64 -d" in joined  # decode step sent
    assert any("LIKEDBG-PROBE" in s for s in sess.sent)  # probe sent


def test_extract_vmlinux_quotes_filename_with_space(tmp_path: Path) -> None:
    from likedbg.foreign import extract_vmlinux

    image_path = tmp_path / "in" / "my image.bzImage"
    image_path.parent.mkdir()
    image_path.write_bytes(b"MZfake-bzImage")
    out = tmp_path / "out" / "vmlinux"
    c = _FakeContainer(make_out=out)

    extract_vmlinux(c, image_path, out, image="like_musl:latest")

    cmd = " ".join(c.execs)
    assert "'/in/my image.bzImage'" in cmd


# ---- kallsyms symbol recovery (ADR-0015) ----


def _write_bzimage(path: Path) -> None:
    """A minimal x86 bzImage: the boot-protocol 'HdrS' magic at offset 0x202 (what the recovery
    path's _is_x86_bzimage sniff checks); an arm64 Image or junk lacks it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = bytearray(0x210)
    buf[0:2] = b"MZ"
    buf[0x202:0x206] = b"HdrS"
    path.write_bytes(bytes(buf))


def _nm_kernel(n: int = 1500, *, stext: str = "ffffffff81000000") -> str:
    body = "\n".join(f"ffffffff8100{i:04x} T sym{i}" for i in range(n))
    return f"{body}\n{stext} T _stext\n"


def _exec_result(output: str):
    return type("R", (), {"exit_code": 0, "output": output})()


class _RecoverFake:
    """Fake like_musl container: vmlinux-to-elf writes an ELF (or raises), nm returns configured
    output, extract-vmlinux.sh writes carve bytes. Records the ordered exec commands."""

    def __init__(self, *, v2e_elf=b"\x7fELFrecovered", nm_output="", carve_bytes=None, fail_v2e=False):
        self.execs: list[str] = []
        self.run_kwargs: dict | None = None
        self._v2e_elf = v2e_elf
        self._nm = nm_output
        self._carve = carve_bytes
        self._fail_v2e = fail_v2e
        self._outdir: Path | None = None

    def run_detached(self, image, *, volumes=None, **kwargs):
        self.run_kwargs = {"image": image, "volumes": volumes, **kwargs}
        for hd, spec in (volumes or {}).items():
            if spec.get("bind") == "/out":
                self._outdir = Path(hd)
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if "vmlinux-to-elf" in cmd:
            if self._fail_v2e:
                raise ContainerError("vmlinux-to-elf failed")
            if self._v2e_elf is not None and self._outdir is not None:
                (self._outdir / "vmlinux").write_bytes(self._v2e_elf)
        elif cmd.split()[0] == "nm":
            return _exec_result(self._nm)
        elif "extract-vmlinux.sh" in cmd:
            if self._carve is not None and self._outdir is not None:
                (self._outdir / "vmlinux").write_bytes(self._carve)
        return _exec_result("")

    def stop(self, container):
        self.stopped = True


def _stamp(out: Path) -> dict:
    return json.loads((out.parent / (out.name + ".stamp")).read_text())


def test_trust_gate_accepts_real_symtab() -> None:
    ok, reason, count = _trust_gate(_nm_kernel(1500))
    assert ok and reason == "" and count == 1501


def test_trust_gate_rejects_thin_symtab() -> None:
    ok, reason, _ = _trust_gate(_nm_kernel(10))
    assert not ok and "thin symtab" in reason


def test_trust_gate_rejects_missing_stext() -> None:
    body = "\n".join(f"ffffffff8100{i:04x} T sym{i}" for i in range(1500))
    ok, reason, _ = _trust_gate(body)
    assert not ok and reason == "no _stext"


def test_trust_gate_rejects_out_of_range_stext() -> None:
    # 1500 symbols but _stext in userspace VA -> wrong base -> every symbol would be offset -> reject.
    ok, reason, _ = _trust_gate(_nm_kernel(1500, stext="0000000000401000"))
    assert not ok and "out of range" in reason


def test_recovery_success_is_recovered_and_cached(tmp_path: Path) -> None:
    img = tmp_path / "in" / "bzImage"
    _write_bzimage(img)
    out = tmp_path / "out" / "vmlinux"
    c = _RecoverFake(nm_output=_nm_kernel(1500))
    result = extract_vmlinux(c, img, out, image="like_musl:latest")
    assert result == out and out.read_bytes().startswith(b"\x7fELF")
    joined = " ".join(c.execs)
    assert "vmlinux-to-elf" in joined and joined.count("nm ") >= 1 and "extract-vmlinux.sh" not in joined
    assert _stamp(out)["state"] == "RECOVERED"


def test_recovery_thin_symtab_falls_back_to_carve(tmp_path: Path) -> None:
    img = tmp_path / "in" / "bzImage"
    _write_bzimage(img)
    out = tmp_path / "out" / "vmlinux"
    c = _RecoverFake(nm_output=_nm_kernel(5), carve_bytes=b"\x7fELFcarved")
    extract_vmlinux(c, img, out, image="like_musl:latest")
    joined = " ".join(c.execs)
    assert "vmlinux-to-elf" in joined and "extract-vmlinux.sh" in joined  # recovery attempted, then carve
    assert _stamp(out)["state"] == "DECOMPRESSED"


def test_recovery_v2e_failure_falls_back_to_carve(tmp_path: Path) -> None:
    img = tmp_path / "in" / "bzImage"
    _write_bzimage(img)
    out = tmp_path / "out" / "vmlinux"
    c = _RecoverFake(fail_v2e=True, carve_bytes=b"\x7fELFcarved")
    extract_vmlinux(c, img, out, image="like_musl:latest")
    assert "extract-vmlinux.sh" in " ".join(c.execs)
    assert _stamp(out)["state"] == "DECOMPRESSED"


def test_non_bzimage_skips_recovery(tmp_path: Path) -> None:
    img = tmp_path / "in" / "Image"
    img.parent.mkdir()
    img.write_bytes(b"not an x86 bzimage")
    out = tmp_path / "out" / "vmlinux"
    c = _RecoverFake(carve_bytes=b"\x7fELFcarved")
    extract_vmlinux(c, img, out, image="like_musl:latest")
    joined = " ".join(c.execs)
    assert "vmlinux-to-elf" not in joined and "extract-vmlinux.sh" in joined
    assert _stamp(out)["state"] == "DECOMPRESSED"


def test_cache_hit_reuses_without_container(tmp_path: Path) -> None:
    img = tmp_path / "in" / "bzImage"
    _write_bzimage(img)
    out = tmp_path / "out" / "vmlinux"
    out.parent.mkdir(parents=True)
    out.write_bytes(b"\x7fELFcached")
    (out.parent / "vmlinux.stamp").write_text(
        json.dumps({"image_sha256": _image_sha256(img), "v2e_version": V2E_VERSION, "state": "RECOVERED"})
    )
    c = _RecoverFake()
    extract_vmlinux(c, img, out, image="like_musl:latest")
    assert c.execs == []  # cache hit: no container work at all


def test_cache_miss_on_image_change_regenerates(tmp_path: Path) -> None:
    img = tmp_path / "in" / "bzImage"
    _write_bzimage(img)
    out = tmp_path / "out" / "vmlinux"
    out.parent.mkdir(parents=True)
    out.write_bytes(b"\x7fELFold")
    (out.parent / "vmlinux.stamp").write_text(
        json.dumps({"image_sha256": "stale-hash", "v2e_version": V2E_VERSION, "state": "RECOVERED"})
    )
    c = _RecoverFake(nm_output=_nm_kernel(1500))
    extract_vmlinux(c, img, out, image="like_musl:latest")
    assert "vmlinux-to-elf" in " ".join(c.execs)  # stale hash -> regenerated
    assert _stamp(out)["state"] == "RECOVERED"
