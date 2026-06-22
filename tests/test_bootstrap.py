from likedbg.bootstrap import BootstrapProbes
from likedbg.bootstrap import check_prerequisites


def _probes(present=(), colima=False, binfmt=False):
    return BootstrapProbes(
        has=lambda cmd: cmd in present,
        colima_running=lambda: colima,
        binfmt_arm64=lambda: binfmt,
    )


def test_macos_all_present_all_ok():
    p = _probes(present={"colima", "qemu-system-aarch64", "uv"}, colima=True, binfmt=True)
    results = check_prerequisites("darwin", p)
    assert all(r.ok for r in results)


def test_macos_missing_qemu_reports_remedy():
    p = _probes(present={"colima", "uv"}, colima=True, binfmt=True)
    results = check_prerequisites("darwin", p)
    qemu = next(r for r in results if "qemu" in r.name)
    assert qemu.ok is False and qemu.remedy and "brew" in qemu.remedy


def test_macos_colima_installed_but_not_running_is_not_ok():
    p = _probes(present={"colima", "qemu-system-aarch64", "uv"}, colima=False, binfmt=True)
    results = check_prerequisites("darwin", p)
    colima = next(r for r in results if r.name == "colima")
    assert colima.ok is False and colima.remedy and "colima start" in colima.remedy


def test_linux_requires_docker_not_colima():
    p = _probes(present={"docker", "uv"}, binfmt=True)
    names = {r.name for r in check_prerequisites("linux", p)}
    assert "docker" in names and "colima" not in names
