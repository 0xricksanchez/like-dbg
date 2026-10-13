from pathlib import Path

from likedbg.cache import BuildRecipe
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
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "build": {"compiler": "clang"}})
    frags = [_frag(tmp_path, "debug.config", "CONFIG_DEBUG_INFO=y\n")]
    r = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=frags)
    assert isinstance(r, BuildRecipe)
    assert r.arch == "arm64" and r.compiler == "clang"
    assert r.env() == {"ARCH": "arm64", "LLVM": "1"}
    assert r.cache_inputs()["version"] == "6.6.30"
    assert any(k == "frag:configs/fragments/debug.config" for k in r.cache_inputs())
    assert r.label.startswith("linux-6.6.30-") and len(r.label.split("-")[-1]) == 8


def test_build_recipe_label_changes_with_fragment_content(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    a = build_recipe(
        settings,
        version="6.6.30",
        arch="arm64",
        workspace=tmp_path,
        fragments=[_frag(tmp_path, "f.config", "CONFIG_A=y\n")],
    )
    b = build_recipe(
        settings,
        version="6.6.30",
        arch="arm64",
        workspace=tmp_path,
        fragments=[_frag(tmp_path, "f.config", "CONFIG_B=y\n")],
    )
    assert a.label != b.label


def test_build_recipe_label_embeds_kernel_tag(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "build": {"label_suffix": "gef"}})
    r = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    assert r.label.startswith("linux-6.6.30-gef-")


def test_kernel_tag_changes_label_and_key(tmp_path):
    base = Settings.model_validate({"general": {"arch": "arm64"}})
    tagged = Settings.model_validate({"general": {"arch": "arm64"}, "build": {"label_suffix": "gef"}})
    a = build_recipe(base, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    b = build_recipe(tagged, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    assert a.label != b.label
    assert a.key != b.key


def test_rootfs_recipe_label(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "rootfs": {"distribution": "bookworm"}})
    r = rootfs_recipe(settings, arch="arm64")
    assert isinstance(r, RootfsRecipe)
    assert r.label.startswith("rootfs-arm64-bookworm-") and len(r.label.split("-")[-1]) == 8


def test_rootfs_recipe_tracks_rootfs_script_content(tmp_path):
    script = tmp_path / "io" / "scripts" / "rootfs.sh"
    script.parent.mkdir(parents=True)
    script.write_text("first\n")
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "rootfs": {"distribution": "bookworm"}})

    first = rootfs_recipe(settings, arch="arm64", workspace=tmp_path)
    script.write_text("second\n")
    second = rootfs_recipe(settings, arch="arm64", workspace=tmp_path)

    assert "script:io/scripts/rootfs.sh" in first.cache_inputs()
    assert first.label != second.label


def test_normalize_fragment_keeps_directives_drops_comments():
    from likedbg.cache import normalize_fragment

    raw = "# header note\n\nCONFIG_FOO=y   \n# a comment\n# CONFIG_BAR is not set\n"
    assert normalize_fragment(raw) == "CONFIG_FOO=y\n# CONFIG_BAR is not set"


def test_fragment_hash_ignores_comment_only_edits(tmp_path):
    from likedbg.cache import build_recipe
    from likedbg.config import Settings

    rel = _frag(tmp_path, "x.config", "CONFIG_FOO=y\n# note A\n")
    s = Settings()
    h1 = build_recipe(s, version="6.6.30", arch="x86_64", workspace=tmp_path, fragments=[rel]).frag_hashes
    (tmp_path / rel).write_text("CONFIG_FOO=y\n# note B, only a comment changed\n")
    h2 = build_recipe(s, version="6.6.30", arch="x86_64", workspace=tmp_path, fragments=[rel]).frag_hashes
    assert h1 == h2
    (tmp_path / rel).write_text("CONFIG_FOO=n\n")
    h3 = build_recipe(s, version="6.6.30", arch="x86_64", workspace=tmp_path, fragments=[rel]).frag_hashes
    assert h3 != h1


def _recipe(*, arch="arm64", compiler="clang", frags=(), patches=()):
    return BuildRecipe(
        version="6.6.30",
        arch=arch,
        compiler=compiler,
        make_vars=(),
        frag_hashes=tuple((f, "h") for f in frags),
        fragments=frags,
        patch_hashes=patches,
    )


def test_src_key_is_arch_compiler_fragment_independent():
    a = _recipe(arch="arm64", compiler="clang", frags=("f1",))
    b = _recipe(arch="x86_64", compiler="gcc", frags=("f2",))
    assert a.src_key == b.src_key  # same version, no patches -> shared source
    assert a.label != b.label  # but distinct builds
    assert a.src_label == b.src_label


def test_src_key_changes_with_patches():
    a = _recipe(patches=(("p", "h1"),))
    b = _recipe(patches=(("p", "h2"),))
    assert a.src_key != b.src_key
