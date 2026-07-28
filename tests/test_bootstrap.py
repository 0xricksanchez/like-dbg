from likedbg.bootstrap import BootstrapProbes
from likedbg.bootstrap import check_prerequisites


def _probes(present=(), docker_ready=True, binfmt=(), record=None):
    def binfmt_registered(handler: str) -> bool:
        if record is not None:
            record.append(handler)
        return handler in binfmt

    return BootstrapProbes(
        has=lambda cmd: cmd in present,
        docker_ready=lambda: docker_ready,
        binfmt_registered=binfmt_registered,
    )


def test_macos_all_present_nothing_missing():
    p = _probes(present={"docker", "qemu-system-aarch64", "uv"})
    results = check_prerequisites("darwin", p, machine="arm64")
    # binfmt is reported "unknown" on macOS, which is not a failure.
    assert all(r.status != "missing" for r in results)


def test_macos_missing_qemu_reports_remedy():
    p = _probes(present={"docker", "uv"})
    results = check_prerequisites("darwin", p, machine="arm64")
    qemu = next(r for r in results if "qemu-system" in r.name)
    assert qemu.ok is False and qemu.remedy and "brew" in qemu.remedy


def test_macos_accepts_any_docker_engine_not_just_colima():
    """LIKE-DBG talks to the active Docker CLI context, so Docker Desktop and OrbStack are as
    valid as colima. Demanding colima specifically was a false failure for everyone else."""
    p = _probes(present={"docker", "qemu-system-aarch64", "uv"})
    results = check_prerequisites("darwin", p, machine="arm64")
    assert "colima" not in {r.name for r in results}
    assert next(r for r in results if r.name == "docker").ok is True


def test_docker_cli_without_a_running_daemon_is_missing():
    p = _probes(present={"docker", "qemu-system-aarch64", "uv"}, docker_ready=False)
    results = check_prerequisites("darwin", p, machine="arm64")
    docker = next(r for r in results if r.name == "docker")
    assert docker.ok is False and docker.remedy and "no daemon answers" in docker.remedy


def test_linux_requires_docker_not_colima():
    p = _probes(present={"docker", "uv"}, binfmt={"qemu-aarch64"})
    names = {r.name for r in check_prerequisites("linux", p, machine="x86_64")}
    assert "docker" in names and "colima" not in names


# ---- binfmt: the emulator you need is for the arch you do NOT run natively ----


def test_binfmt_target_is_the_foreign_arch_on_x86_64():
    """An x86_64 host runs x86_64 natively; the rootfs build only needs emulation for arm64."""
    seen: list[str] = []
    p = _probes(present={"docker", "uv"}, binfmt={"qemu-aarch64"}, record=seen)
    results = check_prerequisites("linux", p, machine="x86_64")
    binfmt = next(r for r in results if r.name.startswith("binfmt"))
    assert seen == ["qemu-aarch64"]
    assert binfmt.name == "binfmt-aarch64" and binfmt.status == "ok"


def test_binfmt_target_is_x86_64_on_an_arm64_host():
    """Regression: the check hardcoded arm64, which is native on Apple Silicon and arm64 Linux."""
    seen: list[str] = []
    p = _probes(present={"docker", "uv"}, binfmt={"qemu-x86_64"}, record=seen)
    results = check_prerequisites("linux", p, machine="aarch64")
    binfmt = next(r for r in results if r.name.startswith("binfmt"))
    assert seen == ["qemu-x86_64"]
    assert binfmt.name == "binfmt-x86_64" and binfmt.status == "ok"


def test_binfmt_missing_on_linux_reports_the_install_remedy():
    """Regression: the probe was `which docker`, so it always passed and this remedy never printed."""
    p = _probes(present={"docker", "uv"}, binfmt=())
    results = check_prerequisites("linux", p, machine="x86_64")
    binfmt = next(r for r in results if r.name.startswith("binfmt"))
    assert binfmt.status == "missing"
    assert binfmt.remedy and "tonistiigi/binfmt" in binfmt.remedy


def test_binfmt_is_unknown_on_macos_and_the_host_is_never_probed():
    """The handler lives in the Docker VM's kernel, which the host cannot see, so claiming
    either a pass or a failure would be a guess."""
    seen: list[str] = []
    p = _probes(present={"docker", "qemu-system-aarch64", "uv"}, record=seen)
    results = check_prerequisites("darwin", p, machine="arm64")
    binfmt = next(r for r in results if r.name.startswith("binfmt"))
    assert seen == []  # probing the host's /proc would be meaningless
    assert binfmt.status == "unknown" and binfmt.ok is False
    assert binfmt.remedy and "tonistiigi/binfmt" in binfmt.remedy


def test_only_ok_counts_as_ok():
    from likedbg.bootstrap import Prereq

    assert Prereq("x", "ok", None).ok is True
    assert Prereq("x", "missing", "do the thing").ok is False
    assert Prereq("x", "unknown", None).ok is False


def test_main_exits_zero_when_only_unknowns_remain(capsys, monkeypatch):
    """An advisory must not fail `--check`, or a macOS user could never get a green run."""
    from likedbg import bootstrap

    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(
        bootstrap,
        "_real_probes",
        lambda: _probes(present={"docker", "qemu-system-aarch64", "uv"}),
    )
    rc = bootstrap.main(["--check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[note]" in out and "MISSING" not in out


def test_main_exits_one_when_something_is_missing(capsys, monkeypatch):
    from likedbg import bootstrap

    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Linux")
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(bootstrap, "_real_probes", lambda: _probes(present={"uv"}, binfmt=()))
    rc = bootstrap.main(["--check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[MISSING] docker" in out
