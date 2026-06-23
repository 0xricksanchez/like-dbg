import pytest

from likedbg.adopt import adopt_legacy_build
from likedbg.cache import BuildRecipe
from likedbg.cache import manifest_exists
from likedbg.errors import CacheError


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
