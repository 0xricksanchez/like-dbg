from pathlib import Path

import pytest

from likedbg import images
from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGEE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import MUSL_IMAGE
from likedbg.constants import ROOTFS_IMAGE
from likedbg.host_profile import HostProfile
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
    assert {s.tag for s in images.IMAGES} == {
        BASE_IMAGE,
        KBUILDER_IMAGE,
        ROOTFS_IMAGE,
        DEBUGGER_IMAGE,
        DEBUGGEE_IMAGE,
        MUSL_IMAGE,
    }
    for s in images.IMAGES:
        assert s.build_inputs[0] == s.dockerfile  # dockerfile is always input[0]
        assert s.buildargs.get("USER") == "user"  # every image threads USER
    rootfs = next(s for s in images.IMAGES if s.tag == ROOTFS_IMAGE)
    assert "io/scripts/rootfs.sh" in rootfs.build_inputs  # the baked script (prior-bug file)
    debuggee = next(s for s in images.IMAGES if s.tag == DEBUGGEE_IMAGE)
    assert debuggee.dockerfile == ".dockerfile_dbge"


def test_musl_image_registered() -> None:
    tags = [s.tag for s in images.IMAGES]
    assert MUSL_IMAGE in tags
    musl = next(s for s in images.IMAGES if s.tag == MUSL_IMAGE)
    assert musl.dockerfile == ".dockerfile_musl"
    assert "io/scripts/extract-vmlinux.sh" in musl.build_inputs
    # the pinned vmlinux-to-elf is threaded as a build-arg (single source of truth with the cache stamp)
    from likedbg.constants import V2E_VERSION

    assert musl.buildargs.get("V2E_VERSION") == V2E_VERSION


def test_foreign_prep_images_are_base_and_musl() -> None:
    tags = {s.tag for s in images.foreign_prep_images()}
    assert tags == {BASE_IMAGE, MUSL_IMAGE}


def test_required_for_foreign_native_host_excludes_debuggee() -> None:
    from likedbg.constants import DEBUGGEE_IMAGE

    class _H:
        debuggee_mode = "native-host"

    tags = {s.tag for s in images.required_for_foreign(_H())}
    assert MUSL_IMAGE in tags and DEBUGGEE_IMAGE not in tags


def test_required_for_foreign_in_container_includes_debuggee() -> None:
    from likedbg.constants import DEBUGGEE_IMAGE

    class _H:
        debuggee_mode = "in-container"

    tags = {s.tag for s in images.required_for_foreign(_H())}
    assert MUSL_IMAGE in tags and DEBUGGEE_IMAGE in tags


def test_use_images_is_all_possible_cached_run_images_in_order():
    assert tuple(s.tag for s in images.USE_IMAGES) == (BASE_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE, DEBUGGEE_IMAGE)


def _host(mode):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="tcg",
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


def test_required_for_includes_debuggee_only_in_container():
    in_container = {s.tag for s in images.required_for(_host("in-container"))}
    native = {s.tag for s in images.required_for(_host("native-host"))}
    assert DEBUGGEE_IMAGE in in_container
    assert DEBUGGEE_IMAGE not in native
    assert len(native) == 4 and len(in_container) == 5


def test_required_for_use_includes_debuggee_only_in_container():
    in_container = tuple(s.tag for s in images.required_for_use(_host("in-container")))
    native = tuple(s.tag for s in images.required_for_use(_host("native-host")))
    assert in_container == (BASE_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE, DEBUGGEE_IMAGE)
    assert native == (BASE_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE)


def test_copy_sources_parses_literal_local_files():
    text = "FROM x\nRUN echo hi\nCOPY io/scripts/rootfs.sh .\nADD extra.txt /opt/extra.txt\n"
    assert images.copy_sources(text) == ["io/scripts/rootfs.sh", "extra.txt"]


def test_copy_sources_skips_urls_and_multistage():
    text = "COPY --from=builder /out/bin /usr/bin/bin\nADD https://x/y.tgz /tmp/\n"
    assert images.copy_sources(text) == []


def test_copy_sources_does_not_treat_source_substring_as_multistage_flag():
    text = "COPY app--from-builder.txt /opt/app--from-builder.txt\n"
    assert images.copy_sources(text) == ["app--from-builder.txt"]


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


class _FakeContainer:
    def __init__(self, existing=(), labels=None):
        self.existing = set(existing)
        self.labels = labels or {}
        self.builds = []  # list of (dockerfile, tag, labels)

    def image_exists(self, tag):
        return tag in self.existing

    def build_image(self, dockerfile, tag, buildargs, *, nocache=False, labels=None):
        self.builds.append((dockerfile, tag, labels))
        self.existing.add(tag)

    def image_labels(self, tag):
        return self.labels.get(tag, {})


def _two_specs(tmp_path):
    (tmp_path / "Da").write_text("FROM scratch\n")
    (tmp_path / "Db").write_text("FROM a\n")
    return (
        ImageSpec("img_a:latest", "Da", ("Da",), {"USER": "user"}),
        ImageSpec("img_b:latest", "Db", ("Db",), {"USER": "user"}),
    )


def test_build_images_builds_all_in_order_with_label(tmp_path):
    specs = _two_specs(tmp_path)
    c = _FakeContainer()
    images.build_images(c, tmp_path, specs)
    assert [tag for _, tag, _ in c.builds] == ["img_a:latest", "img_b:latest"]
    for spec, (_, _, labels) in zip(specs, c.builds, strict=True):
        assert labels == {images.LABEL: images.input_sha(spec, tmp_path)}


def test_ensure_current_builds_missing_and_returns_no_stale(tmp_path):
    specs = _two_specs(tmp_path)
    c = _FakeContainer()  # nothing exists
    stale = images.ensure_current(c, tmp_path, specs)
    assert stale == []
    assert [tag for _, tag, _ in c.builds] == ["img_a:latest", "img_b:latest"]


def test_ensure_current_flags_stale_without_rebuilding(tmp_path):
    specs = _two_specs(tmp_path)
    fresh_b = images.input_sha(specs[1], tmp_path)
    c = _FakeContainer(
        existing=["img_a:latest", "img_b:latest"],
        labels={"img_a:latest": {images.LABEL: "stale"}, "img_b:latest": {images.LABEL: fresh_b}},
    )
    stale = images.ensure_current(c, tmp_path, specs)
    assert stale == ["img_a:latest"]  # a is stale, b is current
    assert c.builds == []  # stale images are NOT rebuilt (warn-only, ADR-0004)


def test_ensure_current_honors_specs_subset(tmp_path):
    specs = _two_specs(tmp_path)
    c = _FakeContainer()
    images.ensure_current(c, tmp_path, (specs[0],))
    assert [tag for _, tag, _ in c.builds] == ["img_a:latest"]  # only the passed spec touched
