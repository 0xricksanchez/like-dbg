from pathlib import Path

from likedbg.cache import Manifest
from likedbg.stages.profile_verification import read_built_config


def test_reads_host_config_without_container(tmp_path: Path) -> None:
    cfg = tmp_path / "artifacts" / "lbl" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("CONFIG_KASAN=y\n")
    m = Manifest(kind="build", label="lbl", key="k", version="6.6.30", arch="x86_64",
                 storage_mode="volume", kernel_release="6.6.30",
                 paths={"config_host": str(cfg)})
    text, release = read_built_config(m, container=None, workspace=tmp_path)
    assert "CONFIG_KASAN=y" in text and release == "6.6.30"
