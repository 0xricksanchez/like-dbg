"""cmd_prune (`--prune [SIZE]`): target resolution (explicit size / [cache] max_size fallback /
remedy error when neither is set) and protecting the latest run's build from eviction."""

from types import SimpleNamespace

import pytest
from loguru import logger

from likedbg.cache import Manifest
from likedbg.cache import manifest_exists
from likedbg.cache import write_manifest
from likedbg.cli import cmd_prune
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError

G = 1024**3

OLD = "2020-01-01T00:00:00+00:00"
NEW = "2026-01-01T00:00:00+00:00"


class FakeC(ContainerService):
    """No-op container: prune_cache's eviction path (bind storage_mode) never touches it."""

    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _mkbuild(tmp_path, label, *, size_bytes, last_used):
    m = Manifest(
        kind="build",
        label=label,
        key=f"key-{label}",
        version="6.6.30",
        arch="arm64",
        storage_mode="bind",
        size_bytes=size_bytes,
        last_used=last_used,
    )
    write_manifest(tmp_path, m)
    return m


def test_cmd_prune_explicit_size_evicts_to_target(tmp_path):
    _mkbuild(tmp_path, "A", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", size_bytes=5 * G, last_used=NEW)

    rc = cmd_prune(FakeC(), tmp_path, size_arg="6G", max_size="")

    assert rc == 0
    assert manifest_exists(tmp_path, "build", "A") is False  # oldest evicted to reach the 6G target
    assert manifest_exists(tmp_path, "build", "B") is True


def test_cmd_prune_no_size_arg_falls_back_to_configured_max_size(tmp_path):
    _mkbuild(tmp_path, "A", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", size_bytes=5 * G, last_used=NEW)

    rc = cmd_prune(FakeC(), tmp_path, size_arg="", max_size="6G")

    assert rc == 0
    assert manifest_exists(tmp_path, "build", "A") is False
    assert manifest_exists(tmp_path, "build", "B") is True


def test_cmd_prune_neither_size_arg_nor_max_size_raises_remedy_error(tmp_path):
    with pytest.raises(CacheError) as exc:
        cmd_prune(FakeC(), tmp_path, size_arg="", max_size="")

    assert "--prune needs a size" in exc.value.message
    assert "--prune 30G" in (exc.value.remedy or "")
    assert "max_size" in (exc.value.remedy or "")


def test_cmd_prune_protects_latest_run_build(tmp_path):
    _mkbuild(tmp_path, "A", size_bytes=5 * G, last_used=OLD)
    _mkbuild(tmp_path, "B", size_bytes=5 * G, last_used=OLD)  # same age; only the run.json label protects it
    run_dir = tmp_path / "artifacts" / "runs" / "latest"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"build_label": "B"}')

    rc = cmd_prune(FakeC(), tmp_path, size_arg="0", max_size="")

    assert rc == 0
    assert manifest_exists(tmp_path, "build", "A") is False  # evicted
    assert manifest_exists(tmp_path, "build", "B") is True  # protected via artifacts/runs/latest


def test_cmd_prune_no_latest_run_protects_nothing(tmp_path):
    _mkbuild(tmp_path, "A", size_bytes=5 * G, last_used=OLD)

    rc = cmd_prune(FakeC(), tmp_path, size_arg="0", max_size="")

    assert rc == 0
    assert manifest_exists(tmp_path, "build", "A") is False


def test_cmd_prune_logs_nothing_to_prune_when_already_under_target(tmp_path):
    _mkbuild(tmp_path, "A", size_bytes=1 * G, last_used=OLD)

    messages: list[str] = []
    handler_id = logger.add(messages.append, level="INFO")
    try:
        rc = cmd_prune(FakeC(), tmp_path, size_arg="10G", max_size="")
    finally:
        logger.remove(handler_id)

    assert rc == 0
    assert manifest_exists(tmp_path, "build", "A") is True
    assert any("nothing to prune" in m for m in messages)
