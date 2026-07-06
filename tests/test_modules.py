from likedbg import modules
from likedbg.errors import ModuleError


class FakeExec:
    def __init__(self, exit_code=0, output=""):
        self.exit_code = exit_code
        self.output = output


class FakeContainer:
    """Records run_detached kwargs + exec commands; simulates the .ko appearing."""

    def __init__(self, *, make_rc=0):
        self.run_kwargs = None
        self.execs: list[str] = []
        self._make_rc = make_rc
        self.stopped = False

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return FakeExec(exit_code=0, output="")

    def stop(self, container):
        self.stopped = True


def test_build_module_runs_make_and_returns_ko(tmp_path):
    src = tmp_path / "lk01"
    src.mkdir()
    (src / "lk01.c").write_text("// vuln\n")
    (src / "Makefile").write_text("obj-m += lk01.o\n")
    # simulate kbuild producing the .ko in the source dir (the RW /mod bind maps to src)
    (src / "lk01.ko").write_bytes(b"ELFKO")
    out = tmp_path / "exploit" / "modules"
    c = FakeContainer()
    ko = modules.build_module(
        c,
        src_dir=src,
        kernel_root="/ksrc/linux-6.6.30-abc",
        mount_source="likedbg_ksrc",
        env={"ARCH": "arm64", "LLVM": "1"},
        out_dir=out,
        image="like_kbuilder_arm64:latest",
        volume="likedbg_ksrc",
    )
    assert ko == out / "lk01.ko"
    assert ko.read_bytes() == b"ELFKO"
    # kernel tree RO at /ksrc, module RW at /mod
    vols = c.run_kwargs["volumes"]
    assert vols["likedbg_ksrc"] == {"bind": "/ksrc", "mode": "ro"}
    assert vols[str(src)] == {"bind": "/mod", "mode": "rw"}
    make = " ".join(c.execs)
    assert "make -C /ksrc/linux-6.6.30-abc M=/mod" in make
    assert "ARCH=arm64" in make and "LLVM=1" in make and "modules" in make
    assert c.stopped is True


def test_build_module_raises_when_no_ko(tmp_path):
    src = tmp_path / "brokenmod"
    src.mkdir()
    (src / "Makefile").write_text("obj-m += brokenmod.o\n")  # produces no .ko
    c = FakeContainer()
    try:
        modules.build_module(
            c,
            src_dir=src,
            kernel_root="/ksrc/x",
            mount_source="likedbg_ksrc",
            env={"ARCH": "arm64", "LLVM": "1"},
            out_dir=tmp_path / "out",
            image="img",
            volume="likedbg_ksrc",
        )
        raise AssertionError("expected ModuleError")
    except ModuleError as e:
        assert "no .ko" in str(e).lower() or "produced" in str(e).lower()


def test_module_name_from_modinfo(tmp_path):
    ko = tmp_path / "my-mod.ko"
    ko.write_bytes(b"ELFKO")

    class C:
        def run_detached(self, image, **kw):
            return "CID"

        def exec(self, c, cmd, *, workdir=None):
            return FakeExec(output="my_mod\r\n")  # CRLF, as tty=True

        def stop(self, c):
            pass

    assert modules.module_name(C(), ko, image="img") == "my_mod"


def test_module_name_falls_back_to_stem(tmp_path):
    ko = tmp_path / "foo-bar.ko"
    ko.write_bytes(b"ELFKO")

    class C:
        def run_detached(self, image, **kw):
            return "CID"

        def exec(self, c, cmd, *, workdir=None):
            return FakeExec(output="")  # modinfo yielded nothing

        def stop(self, c):
            pass

    assert modules.module_name(C(), ko, image="img") == "foo_bar"
