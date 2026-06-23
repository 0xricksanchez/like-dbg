from pathlib import Path

import pytest

from likedbg import images
from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import ROOTFS_IMAGE
from likedbg.images import ImageSpec

REPO = Path(__file__).resolve().parents[1]


def test_input_sha_deterministic_and_input_sensitive(tmp_path):
    (tmp_path / "a").write_text("alpha")
    (tmp_path / "b").write_text("beta")
    spec = ImageSpec("t:latest", "a", ("a", "b"), {"USER": "user"})
    h1 = images.input_sha(spec, tmp_path)
    assert h1 == images.input_sha(spec, tmp_path)  # deterministic
    (tmp_path / "b").write_text("BETA")
    assert images.input_sha(spec, tmp_path) != h1  # an input's content changed
    (tmp_path / "b").write_text("beta")
    assert images.input_sha(spec, tmp_path) == h1  # restored


def test_input_sha_ignores_files_not_in_build_inputs(tmp_path):
    (tmp_path / "a").write_text("alpha")
    (tmp_path / "b").write_text("beta")
    spec = ImageSpec("t:latest", "a", ("a",), {"USER": "user"})  # only "a" is an input
    h1 = images.input_sha(spec, tmp_path)
    (tmp_path / "b").write_text("changed")
    assert images.input_sha(spec, tmp_path) == h1


def test_images_manifest_shape():
    assert images.IMAGES[0].tag == BASE_IMAGE  # base first (dependency order)
    assert {s.tag for s in images.IMAGES} == {BASE_IMAGE, KBUILDER_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE}
    for s in images.IMAGES:
        assert s.build_inputs[0] == s.dockerfile  # dockerfile is always input[0]
        assert s.buildargs == {"USER": "user"}
    rootfs = next(s for s in images.IMAGES if s.tag == ROOTFS_IMAGE)
    assert "io/scripts/rootfs.sh" in rootfs.build_inputs  # the baked script (prior-bug file)
    assert all(".dockerfile_dbge" != s.dockerfile for s in images.IMAGES)  # debuggee deferred to B2


def test_use_images_is_base_and_debugger_in_order():
    assert tuple(s.tag for s in images.USE_IMAGES) == (BASE_IMAGE, DEBUGGER_IMAGE)


def test_copy_sources_parses_literal_local_files():
    text = "FROM x\nRUN echo hi\nCOPY io/scripts/rootfs.sh .\nADD extra.txt /opt/extra.txt\n"
    assert images.copy_sources(text) == ["io/scripts/rootfs.sh", "extra.txt"]


def test_copy_sources_skips_urls_and_multistage():
    text = "COPY --from=builder /out/bin /usr/bin/bin\nADD https://x/y.tgz /tmp/\n"
    assert images.copy_sources(text) == []


def test_copy_sources_strict_rejects_glob_and_dir():
    with pytest.raises(ValueError):
        images.copy_sources("COPY io/scripts/*.sh .\n")
    with pytest.raises(ValueError):
        images.copy_sources("COPY io/scripts/ .\n")


def test_build_inputs_cover_every_copy_source():
    # The staleness guard's guard: build_inputs must declare every file a dockerfile bakes in,
    # or input_sha goes blind to it (ADR-0004). Strict: copy_sources raises on unhandled patterns.
    for s in images.IMAGES:
        srcs = images.copy_sources((REPO / s.dockerfile).read_text())
        missing = [c for c in srcs if c not in s.build_inputs]
        assert not missing, f"{s.dockerfile} COPYs {missing} not in build_inputs {s.build_inputs}"
