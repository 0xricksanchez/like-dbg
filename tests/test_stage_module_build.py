from likedbg.config import Settings
from likedbg.stages.module_build import ModuleBuildStage


def _ctx(tmp_path, mods):
    from likedbg.pipeline import PipelineContext

    s = Settings().model_copy(update={"build": Settings().build.model_copy(update={"custom_modules": mods})})
    ctx = PipelineContext(settings=s, host=_host())
    ctx.build_label = "linux-6.6.30-abc"
    ctx.effective_debuggee = s.debuggee  # share_dir="exploit"
    return ctx


def _host():
    from likedbg.host_profile import HostProfile

    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


class FakeC:
    def run_detached(self, image, **kw):
        return "CID"

    def exec(self, c, cmd, *, workdir=None):
        class R:
            exit_code = 0
            output = ""

        return R()

    def stop(self, c):
        pass


def test_should_skip_when_no_modules(tmp_path):
    stage = ModuleBuildStage(
        FakeC(),
        image="img",
        workspace=tmp_path,
        env={"ARCH": "arm64", "LLVM": "1"},
        arch="arm64",
        volume="likedbg_ksrc",
    )
    assert stage.should_skip(_ctx(tmp_path, ())) is True


def test_builds_and_stages_ko(tmp_path, monkeypatch):
    src = tmp_path / "modules" / "lk01"
    src.mkdir(parents=True)
    (src / "lk01.c").write_text("x\n")

    def fake_build(container, *, src_dir, kernel_root, mount_source, env, out_dir, image, volume):
        out_dir.mkdir(parents=True, exist_ok=True)
        ko = out_dir / "lk01.ko"
        ko.write_bytes(b"K")
        return ko

    monkeypatch.setattr("likedbg.modules.build_module", fake_build)
    stage = ModuleBuildStage(
        FakeC(),
        image="img",
        workspace=tmp_path,
        env={"ARCH": "arm64", "LLVM": "1"},
        arch="arm64",
        volume="likedbg_ksrc",
    )
    ctx = _ctx(tmp_path, ("modules/lk01",))
    assert stage.should_skip(ctx) is False
    stage.run(ctx)
    assert (tmp_path / "exploit" / "modules" / "lk01.ko").is_file()


def test_prebuilt_ko_passthrough_copies_without_build(tmp_path, monkeypatch):
    ko_src = tmp_path / "prebuilt" / "given.ko"
    ko_src.parent.mkdir(parents=True)
    ko_src.write_bytes(b"PRE")

    def boom(*a, **k):
        raise AssertionError("must not build a prebuilt .ko")

    monkeypatch.setattr("likedbg.modules.build_module", boom)
    stage = ModuleBuildStage(
        FakeC(),
        image="img",
        workspace=tmp_path,
        env={"ARCH": "arm64", "LLVM": "1"},
        arch="arm64",
        volume="likedbg_ksrc",
    )
    ctx = _ctx(tmp_path, ("prebuilt/given.ko",))
    stage.run(ctx)
    assert (tmp_path / "exploit" / "modules" / "given.ko").read_bytes() == b"PRE"
