from pathlib import Path

from likedbg import modules
from likedbg.errors import ModuleError
from likedbg.guest import GuestEndpoint


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


class FakeGuest:
    """Scriptable guest client mirroring likedbg.guest's module API."""

    def __init__(self):
        self.ran: list[str] = []
        self.pushed: list = []
        self._loaded = False
        self._rmmod_rc = 0
        self._rmmod_err = ""
        self._insmod_rc = 0

    def run(self, ep, cmd, **kw):
        self.ran.append(cmd)

        class R:
            rc = 0
            stdout = ""
            stderr = ""

        r = R()
        if cmd.startswith("test -d /sys/module/"):
            r.stdout = "Y" if self._loaded else "N"
        elif cmd.startswith("rmmod"):
            r.rc = self._rmmod_rc
            r.stderr = self._rmmod_err
        elif cmd.startswith("insmod"):
            r.rc = self._insmod_rc
        elif cmd.startswith("dmesg"):
            r.stdout = "some dmesg\n"
        return r

    def push(self, ep, local, remote, **kw):
        self.pushed.append((local, remote))


def _ep():
    return GuestEndpoint(host="127.0.0.1", port=2222, key=Path("/w/key"))


def test_load_in_place_insmods(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", client=g)
    assert not g.pushed  # under share → in place, no scp
    assert any(c == "insmod /mnt/exploit/modules/lk01.ko" for c in g.ran)


def test_load_scp_when_outside_share(tmp_path):
    share = tmp_path / "exploit"
    share.mkdir()
    ko = tmp_path / "elsewhere" / "lk01.ko"
    ko.parent.mkdir()
    ko.write_bytes(b"K")
    g = FakeGuest()
    modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", client=g)
    assert g.pushed and g.pushed[0][1] == "/mnt/exploit/modules/lk01.ko"


def test_reload_busy_raises_and_keeps_old(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    g._loaded = True
    g._rmmod_rc = 1
    g._rmmod_err = "rmmod: ERROR: Module lk01 is in use"
    try:
        modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", reload=True, client=g)
        raise AssertionError("expected ModuleError")
    except ModuleError as e:
        assert "in use" in str(e).lower() or "busy" in str(e).lower()
    assert not any(c.startswith("insmod") for c in g.ran)  # no duplicate insmod


def test_reload_force_unload_uses_rmmod_f(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    g._loaded = True
    modules.load(
        _ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", reload=True, force_unload=True, client=g
    )
    assert any(c == "rmmod -f lk01" for c in g.ran)
    assert any(c.startswith("insmod") for c in g.ran)


def test_stale_true_when_ko_missing(tmp_path):
    src = tmp_path / "m"
    src.mkdir()
    (src / "m.c").write_text("a\n")
    assert modules.stale(src, tmp_path / "m.ko", "linux-x") is True


def test_record_then_not_stale_until_source_or_label_changes(tmp_path):
    src = tmp_path / "m"
    src.mkdir()
    (src / "m.c").write_text("a\n")
    ko = tmp_path / "m.ko"
    ko.write_bytes(b"K")
    modules.record_hash(src, ko, "linux-x")
    assert modules.stale(src, ko, "linux-x") is False
    (src / "m.c").write_text("b\n")  # source changed
    assert modules.stale(src, ko, "linux-x") is True
    modules.record_hash(src, ko, "linux-x")
    assert modules.stale(src, ko, "linux-y") is True  # kernel label changed


def test_stage_module_reuses_ko_when_source_unchanged(tmp_path, monkeypatch):
    """Second stage_module call for an unchanged source dir must not invoke build_module again."""
    src = tmp_path / "lk01"
    src.mkdir()
    (src / "lk01.c").write_text("x\n")
    (src / "Makefile").write_text("obj-m += lk01.o\n")
    out = tmp_path / "exploit" / "modules"
    calls = {"n": 0}

    def fake_build(container, *, src_dir, kernel_root, mount_source, env, out_dir, image, volume):
        calls["n"] += 1
        out_dir.mkdir(parents=True, exist_ok=True)
        ko = out_dir / "lk01.ko"
        ko.write_bytes(b"K")
        return ko

    monkeypatch.setattr("likedbg.modules.build_module", fake_build)
    ko1 = modules.stage_module(
        object(),
        entry=src,
        out_dir=out,
        kernel_root="/ksrc/x",
        mount_source="likedbg_ksrc",
        env={"ARCH": "arm64", "LLVM": "1"},
        image="img",
        volume="likedbg_ksrc",
        kernel_label="linux-x",
    )
    ko2 = modules.stage_module(  # unchanged source → reuse the staged .ko, no rebuild
        object(),
        entry=src,
        out_dir=out,
        kernel_root="/ksrc/x",
        mount_source="likedbg_ksrc",
        env={"ARCH": "arm64", "LLVM": "1"},
        image="img",
        volume="likedbg_ksrc",
        kernel_label="linux-x",
    )
    assert calls["n"] == 1
    assert ko1 == ko2 == out / "lk01.ko"
