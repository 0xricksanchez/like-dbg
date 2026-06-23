from pathlib import Path

from likedbg.cache import RootfsRecipe
from likedbg.cache import build_recipe
from likedbg.cache import rootfs_recipe
from likedbg.config import Settings


def _frag(tmp_path: Path, name: str, body: str) -> str:
    rel = f"configs/fragments/{name}"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return rel


def test_build_recipe_label_and_inputs(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "kernel_builder": {"compiler": "clang"}})
    frags = [_frag(tmp_path, "debug.config", "CONFIG_DEBUG_INFO=y\n")]
    r = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=frags)
    assert r.arch == "arm64" and r.compiler == "clang"
    assert r.env() == {"ARCH": "arm64", "LLVM": "1"}
    assert r.cache_inputs()["version"] == "6.6.30"
    assert any(k.startswith("frag:debug.config") for k in r.cache_inputs())
    assert r.label.startswith("linux-6.6.30-") and len(r.label.split("-")[-1]) == 8


def test_build_recipe_label_changes_with_fragment_content(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    a = build_recipe(
        settings, version="6.6.30", workspace=tmp_path, fragments=[_frag(tmp_path, "f.config", "CONFIG_A=y\n")]
    )
    b = build_recipe(
        settings, version="6.6.30", workspace=tmp_path, fragments=[_frag(tmp_path, "f.config", "CONFIG_B=y\n")]
    )
    assert a.label != b.label


def test_build_recipe_label_embeds_kernel_tag(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64", "kernel_tag": "gef"}})
    r = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
    assert r.label.startswith("linux-6.6.30-gef-")


def test_rootfs_recipe_label(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "rootfs": {"distribution": "bookworm"}})
    r = rootfs_recipe(settings)
    assert isinstance(r, RootfsRecipe)
    assert r.label.startswith("rootfs-arm64-bookworm-") and len(r.label.split("-")[-1]) == 8
