from types import SimpleNamespace

from loguru import logger

from likedbg.cache import Manifest
from likedbg.cache import cache_total_bytes
from likedbg.cache import drop_orphaned_source
from likedbg.cache import manifest_exists
from likedbg.cache import prune_cache
from likedbg.cache import write_manifest
from likedbg.container_service import ContainerService

G = 1024**3

OLDEST = "2018-01-01T00:00:00+00:00"
OLD = "2020-01-01T00:00:00+00:00"
MID = "2023-01-01T00:00:00+00:00"
NEW = "2026-01-01T00:00:00+00:00"


class FakeC(ContainerService):
    """No-op container: prune_cache's eviction path (bind storage_mode) never touches it,
    but remove_cached/remove_source take a ContainerService regardless."""

    def __init__(self):
        self.execs: list[str] = []

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _mkbuild(tmp_path, label, *, srckey, size_bytes, last_used, storage_mode="bind"):
    m = Manifest(
        kind="build",
        label=label,
        key=f"key-{label}",
        version="6.6.30",
        arch="arm64",
        srckey=srckey,
        storage_mode=storage_mode,
        size_bytes=size_bytes,
        last_used=last_used,
    )
    write_manifest(tmp_path, m)
    return m


def _mksource(tmp_path, label, *, key, size_bytes):
    m = Manifest(kind="source", label=label, key=key, version="6.6.30", arch="arm64", size_bytes=size_bytes)
    write_manifest(tmp_path, m)
    return m


def test_cache_total_bytes_sums_build_and_source(tmp_path):
    _mkbuild(tmp_path, "A", srckey="S", size_bytes=5 * G, last_used=OLD)
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    assert cache_total_bytes(tmp_path) == 6 * G


def test_cache_total_bytes_empty_cache_is_zero(tmp_path):
    assert cache_total_bytes(tmp_path) == 0


def test_prune_noop_when_under_target(tmp_path):
    _mkbuild(tmp_path, "A", srckey="S", size_bytes=1 * G, last_used=OLD)
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()
    evicted = prune_cache(c, tmp_path, 10 * G, protect=set())
    assert evicted == []
    assert manifest_exists(tmp_path, "build", "A") is True


def test_prune_evicts_oldest_nonprotected_keeps_protected_and_shared_source(tmp_path):
    _mkbuild(tmp_path, "A", srckey="S", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", srckey="S", size_bytes=5 * G, last_used=NEW)
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()

    evicted = prune_cache(c, tmp_path, 8 * G, protect={"B"})

    assert evicted == ["A"]
    assert manifest_exists(tmp_path, "build", "A") is False
    assert manifest_exists(tmp_path, "build", "B") is True
    assert manifest_exists(tmp_path, "source", "S") is True  # still ref'd by B
    assert cache_total_bytes(tmp_path) == 6 * G


def test_prune_lru_order_evicts_oldest_first(tmp_path):
    _mkbuild(tmp_path, "A", srckey="SA", size_bytes=5 * G, last_used=MID)
    _mkbuild(tmp_path, "C", srckey="SC", size_bytes=5 * G, last_used=OLDEST)
    _mkbuild(tmp_path, "B", srckey="SB", size_bytes=5 * G, last_used=NEW)
    _mksource(tmp_path, "SA", key="SA", size_bytes=0)
    _mksource(tmp_path, "SC", key="SC", size_bytes=0)
    _mksource(tmp_path, "SB", key="SB", size_bytes=0)
    c = FakeC()

    # total=15G; target fits protected B (5G) + exactly one more non-protected build (10G).
    evicted = prune_cache(c, tmp_path, 10 * G, protect={"B"})

    assert evicted == ["C"]  # the OLDEST, not A (MID)
    assert manifest_exists(tmp_path, "build", "A") is True
    assert manifest_exists(tmp_path, "build", "B") is True
    assert manifest_exists(tmp_path, "build", "C") is False
    # C's source was singly-referenced -> dropped alongside C (refcount 0).
    assert manifest_exists(tmp_path, "source", "SC") is False


def test_prune_treats_empty_last_used_as_oldest(tmp_path):
    _mkbuild(tmp_path, "A", srckey="SA", size_bytes=5 * G, last_used="")  # unstamped/legacy
    _mkbuild(tmp_path, "B", srckey="SB", size_bytes=5 * G, last_used=NEW)
    _mksource(tmp_path, "SA", key="SA", size_bytes=0)
    _mksource(tmp_path, "SB", key="SB", size_bytes=0)
    c = FakeC()

    evicted = prune_cache(c, tmp_path, 5 * G, protect=set())

    assert evicted == ["A"]  # unstamped A treated as oldest, evicted before newer B


def test_prune_target_zero_evicts_all_nonprotected_never_evicts_protected_and_warns(tmp_path):
    _mkbuild(tmp_path, "A", srckey="S", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", srckey="S", size_bytes=5 * G, last_used=NEW)
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()

    messages: list[str] = []
    handler_id = logger.add(messages.append, level="WARNING")
    try:
        evicted = prune_cache(c, tmp_path, 0, protect={"B"})
    finally:
        logger.remove(handler_id)

    assert evicted == ["A"]
    assert manifest_exists(tmp_path, "build", "B") is True  # protected, never evicted
    assert cache_total_bytes(tmp_path) > 0  # B + S still over the target=0
    assert messages  # warned instead of raising


def test_prune_all_builds_protected_evicts_nothing_and_warns(tmp_path):
    _mkbuild(tmp_path, "A", srckey="S", size_bytes=5 * G, last_used=OLD)
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()

    messages: list[str] = []
    handler_id = logger.add(messages.append, level="WARNING")
    try:
        evicted = prune_cache(c, tmp_path, 0, protect={"A"})
    finally:
        logger.remove(handler_id)

    assert evicted == []  # protect set fully honored: nothing evictable at all
    assert manifest_exists(tmp_path, "build", "A") is True
    assert messages


def test_prune_protect_set_never_appears_in_evicted_list(tmp_path):
    _mkbuild(tmp_path, "A", srckey="SA", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", srckey="SB", size_bytes=5 * G, last_used=NEW)
    _mksource(tmp_path, "SA", key="SA", size_bytes=0)
    _mksource(tmp_path, "SB", key="SB", size_bytes=0)
    c = FakeC()

    evicted = prune_cache(c, tmp_path, 0, protect={"A", "B"})

    assert "A" not in evicted
    assert "B" not in evicted
    assert evicted == []


def test_drop_orphaned_source_returns_label_when_dropped(tmp_path):
    # `build` mirrors prune_cache's real call order: remove_cached has already unlinked A's own
    # manifest by the time drop_orphaned_source runs, so A is NOT (re)written to the registry here.
    build = Manifest(
        kind="build", label="A", key="key-A", version="6.6.30", arch="arm64", srckey="S", storage_mode="bind"
    )
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()

    label = drop_orphaned_source(c, tmp_path, build, volume="likedbg_ksrc")

    assert label == "S"
    assert manifest_exists(tmp_path, "source", "S") is False


def test_drop_orphaned_source_returns_none_when_still_referenced(tmp_path):
    build_a = Manifest(
        kind="build", label="A", key="key-A", version="6.6.30", arch="arm64", srckey="S", storage_mode="bind"
    )
    _mkbuild(tmp_path, "B", srckey="S", size_bytes=1 * G, last_used=NEW)  # still references S -> refcount 1
    _mksource(tmp_path, "S", key="S", size_bytes=1 * G)
    c = FakeC()

    label = drop_orphaned_source(c, tmp_path, build_a, volume="likedbg_ksrc")

    assert label is None
    assert manifest_exists(tmp_path, "source", "S") is True


def test_drop_orphaned_source_returns_none_when_no_srckey(tmp_path):
    build = Manifest(
        kind="build", label="A", key="key-A", version="6.6.30", arch="arm64", srckey="", storage_mode="bind"
    )
    c = FakeC()

    assert drop_orphaned_source(c, tmp_path, build, volume="likedbg_ksrc") is None
