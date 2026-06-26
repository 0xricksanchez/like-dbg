from pathlib import Path

from likedbg.cache import build_recipe
from likedbg.config import BuildCfg
from likedbg.config import GeneralCfg
from likedbg.config import Settings


def test_build_recipe_uses_explicit_arch_not_native(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    s = Settings(general=GeneralCfg(arch="native"))
    r = build_recipe(s, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[frag])
    assert r.arch == "arm64"
    assert r.label.startswith("linux-6.6.30-")


def test_patch_dir_changes_cache_key(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    patches = tmp_path / "patches" / "uaf"
    patches.mkdir(parents=True)
    (patches / "0001.patch").write_text("--- a\n+++ b\n")
    s = Settings(build=BuildCfg(patch_dirs=("patches/uaf",)))
    r1 = build_recipe(
        s,
        version="6.6.30",
        arch="x86_64",
        workspace=tmp_path,
        fragments=[frag],
        patch_dirs=("patches/uaf",),
    )
    (patches / "0001.patch").write_text("--- a\n+++ b\n+changed\n")
    r2 = build_recipe(
        s,
        version="6.6.30",
        arch="x86_64",
        workspace=tmp_path,
        fragments=[frag],
        patch_dirs=("patches/uaf",),
    )
    assert r1.key != r2.key
