import json

import pytest

from likedbg import cli
from likedbg.cli import build_foreign_pipeline
from likedbg.container_service import ContainerService
from likedbg.errors import LikeDbgError
from likedbg.foreign import ForeignError
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
    name = "LIKE-DBG-test"

    def __init__(self):
        self.options = {}
        self._panes = iter(["%2", "%3"])

    def current_pane_id(self):
        return "%1"

    def unset_option(self, k):
        pass

    def set_option(self, k, v):
        self.options[k] = v

    def run_in_new_pane(self, *, target, direction, percent, cmd, full=False):
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


def test_build_foreign_pipeline_threads_force_rebuild(tmp_path):
    pipe = build_foreign_pipeline(
        _FakeContainer(),
        _FakeSession(),  # type: ignore[arg-type]
        host=_host(),
        workspace=tmp_path,
        foreign=_fk(tmp_path),
        exploit=tmp_path / "exp.c",
        qemu_extra=(),
        gdb_mount_source=str(tmp_path),
        out_dir=tmp_path / "stage",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        musl_image="like_musl:latest",
        recorder=None,
        force_rebuild=True,
    )
    repack = next(s for s in pipe._stages if s.name == "foreign-repack")  # type: ignore[attr-defined]
    assert repack._force is True
    assert repack._workspace == tmp_path


class _FakeRecorder:
    def __init__(self, workspace):
        self.run_dir = workspace / "artifacts" / "runs" / "fake"
        self.likedbg_log = workspace / "log"
        self.debuggee_pane_log = workspace / "d.log"
        self.debugger_pane_log = workspace / "g.log"
        self.crash_dir = workspace / "crash"

    def record_kernel_paths(self, **kw):
        pass


def _write_project(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "profiles").mkdir()
    (tmp_path / "configs" / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
    )
    (tmp_path / "configs" / "default.toml").write_text('[general]\narch = "native"\n')
    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x3e\x00" + b"\x00" * 20
    )
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    sc = tmp_path / "configs" / "scenarios"
    sc.mkdir()
    (sc / "lk01.toml").write_text(
        '[foreign]\nimage = "bzImage"\nvmlinux = "vmlinux"\n'
        'initramfs = "initramfs.cpio.gz"\ncmdline = "quiet console=ttyS0"\n'
    )
    return sc / "lk01.toml"


def test_cmd_foreign_runs_pipeline(tmp_path, monkeypatch):
    scenario = _write_project(tmp_path)
    ran = {}

    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: [])
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host(target_arch=s.general.arch)))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)

    def _fake_start(*, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles):
        ran["run_resolution"] = run_resolution
        return _FakeRecorder(workspace)

    monkeypatch.setattr(cli.RunRecorder, "start", staticmethod(_fake_start))

    class _Pipe:
        def run(self, ctx):
            ran["ctx"] = ctx

    monkeypatch.setattr(cli, "build_foreign_pipeline", lambda *a, **k: _Pipe())

    session = _FakeSession()
    rc = cli.cmd_foreign(_FakeContainer(), session, tmp_path, scenario=scenario)
    assert rc == 0
    assert ran["ctx"].host.target_arch == "x86_64"  # arch injected from the vmlinux ELF
    request = json.loads(session.options["@likedbg_rerun_request"])
    assert request["scenario"] == str(scenario.resolve())
    assert session.options["@likedbg_active_run_dir"].endswith("artifacts/runs/fake")


def _run_cmd_foreign_capturing_force(tmp_path, monkeypatch, *, stale: list[str], force_rebuild: bool = False) -> dict:
    """Run cmd_foreign with `stale` reported by _ensure_images; capture the force each Stamp got."""
    scenario = _write_project(tmp_path)
    seen: dict = {"log": []}

    monkeypatch.setattr(
        cli,
        "_ensure_images",
        lambda container, workspace, *, specs: [t for t in stale if any(s.tag == t for s in specs)],
    )
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host(target_arch=s.general.arch)))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(cli.logger, "info", lambda msg: seen["log"].append(msg))
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(lambda *, workspace, **kw: _FakeRecorder(workspace)),
    )

    real_resolve = cli.resolve_foreign

    def _capturing_resolve(container, cfg, workspace, *, out_dir, image, force=False):
        seen["resolve_force"] = force
        return real_resolve(container, cfg, workspace, out_dir=out_dir, image=image, force=force)

    monkeypatch.setattr(cli, "resolve_foreign", _capturing_resolve)

    class _Pipe:
        def run(self, ctx):
            pass

    def _capturing_pipeline(*a, **k):
        seen["repack_force"] = k["force_rebuild"]
        return _Pipe()

    monkeypatch.setattr(cli, "build_foreign_pipeline", _capturing_pipeline)

    assert (
        cli.cmd_foreign(_FakeContainer(), _FakeSession(), tmp_path, scenario=scenario, force_rebuild=force_rebuild) == 0
    )
    return seen


def test_cmd_foreign_forces_both_stamps_when_the_musl_image_is_stale(tmp_path, monkeypatch):
    """A stale like_musl is the one input that can make a Stamp LIE. `images.ensure_current` is
    warn-only, so the repack would run in the OLD image while stamping the NEW musl_image_sha (a
    hash of the image's build FILES); after the `--build-images` the warning asks for, that sha is
    unchanged and every later boot reuses an initramfs built by the previous toolchain."""
    seen = _run_cmd_foreign_capturing_force(tmp_path, monkeypatch, stale=[cli.MUSL_IMAGE])
    assert seen["resolve_force"] is True  # the vmlinux Stamp (extract-vmlinux.sh lives in that image)
    assert seen["repack_force"] is True  # the repack Stamp
    assert any(cli.MUSL_IMAGE in ln and "stale" in ln for ln in seen["log"])  # told apart from a plain rebuild


def test_cmd_foreign_threads_force_rebuild_to_both_foreign_stamps(tmp_path, monkeypatch):
    """--force-rebuild reaches BOTH Stamps on a foreign run (ADR-0018): the repack's, and the
    auto-extracted vmlinux's via resolve_foreign. Dropping either hop is silent -- the run still
    boots, on the artifacts the user just asked to discard."""
    seen = _run_cmd_foreign_capturing_force(tmp_path, monkeypatch, stale=[], force_rebuild=True)
    assert seen["resolve_force"] is True
    assert seen["repack_force"] is True


def test_cmd_foreign_does_not_force_for_an_unrelated_stale_image(tmp_path, monkeypatch):
    """Only like_musl feeds the foreign artifacts. A stale debugger/rootfs image must not throw
    away the repack the Stamp exists to skip."""
    seen = _run_cmd_foreign_capturing_force(tmp_path, monkeypatch, stale=["like_debugger:latest"])
    assert seen["resolve_force"] is False
    assert seen["repack_force"] is False


def test_cmd_foreign_forces_serial_only_no_guest_net_or_share(tmp_path, monkeypatch):
    """ADR-0010: a foreign guest exposes only the serial console. Regression test for the
    finding that cmd_foreign left guest_net/share at their (True) defaults, which both
    perturbed the QEMU device model (unsolicited -netdev/-virtfs) and made RunRecorder.start
    write a run.json `guest` block that --run/--insmod/--rmmod would then try (and fail) to
    SSH into, instead of refusing cleanly on a missing guest block."""
    scenario = _write_project(tmp_path)
    ran = {}

    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: [])
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host(target_arch=s.general.arch)))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)

    def _fake_start(*, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles):
        ran["run_resolution"] = run_resolution
        return _FakeRecorder(workspace)

    monkeypatch.setattr(cli.RunRecorder, "start", staticmethod(_fake_start))

    class _Pipe:
        def run(self, ctx):
            ran["ctx"] = ctx

    monkeypatch.setattr(cli, "build_foreign_pipeline", lambda *a, **k: _Pipe())

    rc = cli.cmd_foreign(_FakeContainer(), _FakeSession(), tmp_path, scenario=scenario)
    assert rc == 0

    # Seam 1: the PipelineContext's effective_debuggee feeds build_qemu_argv in DebuggeeStage.
    eff = ran["ctx"].effective_debuggee
    assert eff is not None
    assert eff.guest_net is False
    assert eff.share is False

    # Seam 2: RunRecorder.start reads run_resolution.effective_debuggee to decide whether to
    # write a `guest` block into run.json — must be the same forced-off values.
    rr_eff = ran["run_resolution"].effective_debuggee
    assert rr_eff.guest_net is False
    assert rr_eff.share is False


def _stub_main_foreign_dispatch(tmp_path, monkeypatch, seen: dict):
    """Patch main() down to the cmd_foreign call, CAPTURING the kwargs it is dispatched with."""
    _write_project(tmp_path)
    monkeypatch.setattr(cli, "cmd_foreign", lambda *a, **k: seen.update(hit=True, kwargs=k) or 0)
    monkeypatch.setattr(cli.os, "getenv", lambda k, d=None: "1" if k == "TMUX" else d)
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: object())
    monkeypatch.setattr(cli, "ContainerService", lambda client: _FakeContainer())
    monkeypatch.setattr(cli.Path, "cwd", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(cli.Session, "start", lambda self, name: None)


def test_main_dispatches_to_cmd_foreign_when_image_set(tmp_path, monkeypatch):
    seen: dict = {}
    _stub_main_foreign_dispatch(tmp_path, monkeypatch, seen)
    rc = cli.main(["-c", "lk01"])
    assert seen.get("hit") and rc == 0
    assert seen["kwargs"]["force_rebuild"] is False  # a plain foreign run never forces


def test_main_passes_force_rebuild_through_to_cmd_foreign(tmp_path, monkeypatch):
    """The typed --force-rebuild must REACH cmd_foreign: it is the only way to invalidate the
    foreign path's Stamps (ADR-0018), and dropping the kwarg here fails silently -- the run still
    boots, it just quietly reuses the artifacts the user asked to rebuild."""
    seen: dict = {}
    _stub_main_foreign_dispatch(tmp_path, monkeypatch, seen)
    rc = cli.main(["-c", "lk01", "--force-rebuild"])
    assert rc == 0
    assert seen["kwargs"]["force_rebuild"] is True


class _FakeUploadSession:
    def __init__(self, name):
        self.name = name

    def get_option(self, key):
        assert key == "@likedbg_debuggee_pane"
        return "%7"


def test_cmd_upload_run_not_found_raises(tmp_path):
    with pytest.raises(LikeDbgError):
        cli.cmd_upload(tmp_path, run_id="latest", file="expl")


def test_cmd_upload_calls_console_upload_with_resolved_pane(tmp_path, monkeypatch):
    run_dir = tmp_path / "artifacts" / "runs" / "r1"
    (run_dir / "logs").mkdir(parents=True)
    (run_dir / "logs" / "console.raw").write_text("boot log\n")
    exploit = tmp_path / "expl"
    exploit.write_bytes(b"\x7fELF")

    captured: dict = {}

    def fake_console_upload(session, pane, file, *, read_console):
        captured.update(session=session, pane=pane, file=file, read_console=read_console)

    monkeypatch.setattr(cli, "Session", _FakeUploadSession)
    monkeypatch.setattr(cli, "console_upload", fake_console_upload)

    rc = cli.cmd_upload(tmp_path, run_id="r1", file=str(exploit))

    assert rc == 0
    assert captured["pane"] == "%7"
    assert captured["file"] == exploit
    assert callable(captured["read_console"])


def test_cmd_upload_no_pane_raises_foreign_error(tmp_path, monkeypatch):
    run_dir = tmp_path / "artifacts" / "runs" / "r1"
    (run_dir / "logs").mkdir(parents=True)

    class _NoPaneSession:
        def __init__(self, name):
            pass

        def get_option(self, key):
            return ""

    monkeypatch.setattr(cli, "Session", _NoPaneSession)
    with pytest.raises(ForeignError):
        cli.cmd_upload(tmp_path, run_id="r1", file="expl")


def test_cmd_upload_compiles_c_before_console_upload(tmp_path, monkeypatch):
    run_dir = tmp_path / "artifacts" / "runs" / "r1"
    (run_dir / "logs").mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status":"launched"}')
    (run_dir / "host.json").write_text('{"target_arch":"x86_64","storage_mode":"volume"}')
    (tmp_path / "artifacts" / "runs" / "latest").symlink_to(run_dir)
    src = tmp_path / "expl.c"
    src.write_text("int main(void){}\n")

    seen = {}
    monkeypatch.setattr(cli, "_ensure_images", lambda *a, **k: None)
    monkeypatch.setattr(cli, "ContainerService", lambda *a, **k: object())
    monkeypatch.setattr(cli.docker_env, "make_client", lambda **k: object())

    def fake_compile(container, *, src, arch, out, image, extra_flags=()):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"\x7fELF")
        seen.update(arch=arch, extra_flags=extra_flags)
        return out

    monkeypatch.setattr(cli, "compile_exploit", fake_compile)
    monkeypatch.setattr(cli, "console_upload", lambda session, pane, f, *, read_console: seen.update(uploaded=f))
    monkeypatch.setattr(cli.Session, "get_option", lambda self, k: "%2")

    assert cli.cmd_upload(tmp_path, run_id="latest", file=str(src)) == 0
    assert seen["arch"] == "x86_64"
    assert seen["uploaded"].read_bytes() == b"\x7fELF"  # the compiled binary, not the .c


def _forbid_docker(monkeypatch):
    """Make any Docker construction fail loudly, regardless of whether a real Docker daemon is
    reachable on the test host. Mirrors tests/test_cli_run.py::_forbid_docker, applied here to
    the equivalent `--upload` lazy-container guarantee: cli.cmd_upload must construct a Docker
    ContainerService ONLY when the uploaded file is a `.c` source needing an in-container
    compile. A prebuilt-binary `--upload ./expl` must touch no Docker at all."""

    def _boom(what):
        def _raise(*_a, **_k):
            raise AssertionError(f"binary --upload must NOT {what}")

        return _raise

    monkeypatch.setattr(cli, "ContainerService", _boom("construct a container"))
    monkeypatch.setattr(cli.docker_env, "make_client", _boom("touch Docker (make_client)"))
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", _boom("touch Docker (resolve_docker_host)"))


def test_cmd_upload_binary_path_never_touches_docker(tmp_path, monkeypatch):
    run_dir = tmp_path / "artifacts" / "runs" / "r1"
    (run_dir / "logs").mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status":"launched"}')
    (tmp_path / "artifacts" / "runs" / "latest").symlink_to(run_dir)

    _forbid_docker(monkeypatch)

    expl = tmp_path / "expl"
    expl.write_bytes(b"\x7fELF")

    seen: dict = {}
    monkeypatch.setattr(cli.Session, "get_option", lambda self, k: "%2")
    monkeypatch.setattr(cli, "console_upload", lambda session, pane, f, *, read_console: seen.update(uploaded=f))

    rc = cli.cmd_upload(tmp_path, run_id="latest", file=str(expl))

    assert rc == 0
    assert seen["uploaded"] == expl
