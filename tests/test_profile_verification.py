from pathlib import Path

import pytest

from likedbg.cache import Manifest
from likedbg.cache import write_manifest
from likedbg.config import Settings
from likedbg.debug_profiles import Expect
from likedbg.debug_profiles import ResolvedDebugProfiles
from likedbg.debug_profiles import RunResolution
from likedbg.errors import BuildError
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes
from likedbg.pipeline import PipelineContext
from likedbg.stages.profile_verification import ProfileVerificationStage
from likedbg.stages.profile_verification import read_built_config


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
