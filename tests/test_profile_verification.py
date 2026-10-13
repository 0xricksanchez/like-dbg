from pathlib import Path
from types import SimpleNamespace

import pytest

from likedbg.cache import Manifest
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.debug_profiles import Expect
from likedbg.debug_profiles import ResolvedDebugProfiles
from likedbg.debug_profiles import RunResolution
from likedbg.errors import BuildError
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes
from likedbg.pipeline import PipelineContext
from likedbg.stages.profile_verification import ProfileVerificationStage
from likedbg.stages.profile_verification import read_built_config


class _FakeContainer(ContainerService):
    """Records exec commands; used to pin the legacy .config-read fallback path."""

    def __init__(self) -> None:
        self.execs: list[str] = []

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if cmd.startswith("cat "):
            return SimpleNamespace(exit_code=0, output="CONFIG_FOO=y\n")
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_legacy_fallback_reads_config_from_objdir(tmp_path: Path) -> None:
    """Legacy manifests (no config_host) fall back to a container read of
    <kernel_root>/.config; kernel_root is now the objdir (obj/<label>), not the old
    flat <label>/ tree (cache.locations(), Task 4)."""
    label = "linux-6.6.30-a1b2c3d4"
    objdir = f"{VOLUME_MOUNT}/obj/{label}"
    m = Manifest(
        kind="build",
        label=label,
        key="k",
        version="6.6.30",
        arch="x86_64",
        storage_mode="volume",
        kernel_release="6.6.30",
        paths={"kernel_root": objdir},
    )
    c = _FakeContainer()
    text, release = read_built_config(m, container=c, workspace=tmp_path)
    assert any(cmd == f"cat {objdir}/.config" for cmd in c.execs)
    assert "CONFIG_FOO=y" in text
    assert release == "6.6.30"


def test_reads_host_config_without_container(tmp_path: Path) -> None:
    cfg = tmp_path / "artifacts" / "lbl" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("CONFIG_KASAN=y\n")
    m = Manifest(
        kind="build",
        label="lbl",
        key="k",
        version="6.6.30",
        arch="x86_64",
        storage_mode="volume",
        kernel_release="6.6.30",
        paths={"config_host": str(cfg)},
    )
    text, release = read_built_config(m, container=None, workspace=tmp_path)
    assert "CONFIG_KASAN=y" in text and release == "6.6.30"


def _rr(*exp: Expect) -> RunResolution:
    return RunResolution(
        requested_settings=Settings(),
        provenance={},
        target_arch="x86_64",
        profiles=ResolvedDebugProfiles(
            names=("exploit-dev",),
            base="exploit-dev",
            expected_config=tuple(exp),
            future_breakpoint_groups=(),
        ),
        fragments=(),
        effective_debuggee=Settings().debuggee,
        runtime_defaults={},
        runtime_overrides=(),
        extra_boot_args=(),
        profile_warnings=(),
        runtime_notes=(),
        implied_by={},
    )


def _host(tmp_path: Path) -> HostProfile:
    p = Probes(
        system=lambda: "linux",
        machine=lambda: "x86_64",
        kvm_accessible=lambda: False,
        hvf_supported=lambda: False,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )
    return HostProfile.detect(Settings(), tmp_path, p)


def _seed(tmp_path: Path, body: str) -> Manifest:
    cfg = tmp_path / "artifacts" / "lbl" / "config"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(body)
    m = Manifest(
        kind="build",
        label="lbl",
        key="k",
        version="6.6.30",
        arch="x86_64",
        storage_mode="volume",
        kernel_release="6.6.30",
        paths={"config_host": str(cfg)},
    )
    write_manifest(tmp_path, m)
    return m


def test_hard_failure_raises_build_error(tmp_path: Path) -> None:
    _seed(tmp_path, "# CONFIG_KASAN is not set\n")
    stage = ProfileVerificationStage(None, workspace=tmp_path, kernel_volume="vol")
    ctx = PipelineContext(
        settings=Settings(),
        host=_host(tmp_path),
        build_label="lbl",
        run_resolution=_rr(Expect(symbol="CONFIG_KASAN", value="y", severity="hard")),
    )
    with pytest.raises(BuildError):
        stage.run(ctx)


def test_pass_returns_ctx(tmp_path: Path) -> None:
    _seed(tmp_path, "CONFIG_KASAN=y\n")
    stage = ProfileVerificationStage(None, workspace=tmp_path, kernel_volume="vol")
    ctx = PipelineContext(
        settings=Settings(),
        host=_host(tmp_path),
        build_label="lbl",
        run_resolution=_rr(Expect(symbol="CONFIG_KASAN", value="y", severity="hard")),
    )
    assert stage.run(ctx) is ctx
