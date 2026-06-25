import pytest

from likedbg.adopt import _parse_makefile_version
from likedbg.adopt import adopt_legacy_build
from likedbg.adopt import adopt_legacy_rootfs
from likedbg.cache import BuildRecipe
from likedbg.cache import RootfsRecipe
from likedbg.cache import load_manifest
from likedbg.cache import manifest_exists
from likedbg.errors import CacheError
from likedbg.stages.rootfs import rootfs_target


class _AdoptFakeC:
    def __init__(self, version="6.6.30", cc="clang version 18.1.3"):
        self.execs = []
        self._version, self._cc = version, cc

    def run_detached(self, image, **kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        from types import SimpleNamespace

        self.execs.append(cmd)
        if "Makefile" in cmd:
            out = (
                "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\n"
                if self._version == "6.6.30"
                else "VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 0\n"
            )
        elif "CC_VERSION_TEXT" in cmd:
            out = f'CONFIG_CC_VERSION_TEXT="{self._cc}"\n'
        else:
            out = ""
        return SimpleNamespace(exit_code=0, output=out)

    def stop(self, container):
        pass


def _recipe(compiler="clang"):
    return BuildRecipe(
        version="6.6.30",
        arch="arm64",
        compiler=compiler,
        make_vars=(("ARCH", "arm64"),),
        frag_hashes=(),
        fragments=(),
    )


def _rootfs_recipe():
    return RootfsRecipe(arch="arm64", distribution="bookworm", hostname="LIKE-DBG")


def test_adopt_success_moves_and_writes_manifest(tmp_path):
    c = _AdoptFakeC()
    label = adopt_legacy_build(c, workspace=tmp_path, recipe=_recipe())
    assert label == _recipe().label
    assert any("mv /ksrc/linux-6.6.30 " in e for e in c.execs)
    assert manifest_exists(tmp_path, "build", label) is True


def test_adopt_refuses_on_version_mismatch(tmp_path):
    with pytest.raises(CacheError):
        adopt_legacy_build(_AdoptFakeC(version="6.1.0"), workspace=tmp_path, recipe=_recipe())


def test_adopt_refuses_on_compiler_mismatch(tmp_path):
    with pytest.raises(CacheError):
        adopt_legacy_build(_AdoptFakeC(cc="gcc (Debian 12.2.0)"), workspace=tmp_path, recipe=_recipe("clang"))


def test_parse_makefile_version_parses_valid():
    assert _parse_makefile_version("VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\n") == "6.6.30"


def test_parse_makefile_version_raises_on_missing_field():
    with pytest.raises(CacheError):
        _parse_makefile_version("VERSION = 6\nPATCHLEVEL = 6\n")  # SUBLEVEL missing


def test_adopt_rootfs_uses_default_legacy_source_and_writes_manifest(tmp_path):
    recipe = _rootfs_recipe()
    source = tmp_path / "artifacts" / "rootfs-arm64.img"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"rootfs")

    label = adopt_legacy_rootfs(workspace=tmp_path, recipe=recipe)

    target = rootfs_target(tmp_path, recipe.label)
    manifest = load_manifest(tmp_path, "rootfs", label)
    assert label == recipe.label
    assert target.read_bytes() == b"rootfs"
    assert manifest.key == recipe.key
    assert manifest.inputs == recipe.cache_inputs()
    assert manifest.paths["image_host"] == str(target)


def test_adopt_rootfs_accepts_explicit_source(tmp_path):
    recipe = _rootfs_recipe()
    source = tmp_path / "legacy.img"
    source.write_bytes(b"explicit")

    label = adopt_legacy_rootfs(workspace=tmp_path, recipe=recipe, source=source)

    assert rootfs_target(tmp_path, label).read_bytes() == b"explicit"


def test_adopt_rootfs_missing_source_raises_cache_error(tmp_path):
    with pytest.raises(CacheError) as exc:
        adopt_legacy_rootfs(workspace=tmp_path, recipe=_rootfs_recipe())
    assert "--adopt-rootfs <path>" in (exc.value.remedy or "")
