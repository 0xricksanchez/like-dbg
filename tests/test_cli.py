import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from loguru import logger

import likedbg.cli as cli
from likedbg import cache
from likedbg import guest
from likedbg.cache import Manifest
from likedbg.cache import build_recipe
from likedbg.cache import rootfs_recipe
from likedbg.cache import write_manifest
from likedbg.cli import build_foreign_pipeline
from likedbg.cli import build_pipeline
from likedbg.cli import build_use_pipeline
from likedbg.cli import cmd_clean
from likedbg.cli import summarize_cache
from likedbg.config import ConfigResolution
from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.errors import ConfigError
from likedbg.errors import SessionError
from likedbg.foreign import ForeignKernel
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.rootfs import rootfs_target

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _host(mode):
    return HostProfile(
        os="linux",
        host_arch="arm64",
        target_arch="arm64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode=mode,
        gdbstub_addr="localhost",
    )


def _make_project(tmp_path: Path) -> None:
    """Minimal project layout with a default.toml and an exploit-dev profile."""
    cfgs = tmp_path / "configs"
    (cfgs / "fragments" / "profiles").mkdir(parents=True)
    (cfgs / "profiles").mkdir(parents=True)
    (cfgs / "default.toml").write_text('[source]\nkind="mmp"\nvalue="6.6.30"\n')
    (cfgs / "fragments" / "generic.config").write_text("CONFIG_X=y\n")
    (cfgs / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\nfragments=["configs/fragments/generic.config"]\n'
    )


def _config_resolution(tmp_path: Path) -> ConfigResolution:
    """Return a real ConfigResolution built from a minimal temp project."""
    _make_project(tmp_path)
    from likedbg.config import load_config

    return load_config(tmp_path)


class _FakeSession:
    def __init__(self):
        self.options: list[tuple[str, str]] = []
        self.unset_options: list[str] = []
        self.pane_launches: list[dict[str, object]] = []
        self.pipe_pane_calls: list[dict[str, object]] = []
        self._panes = iter(["%2", "%3"])

    def current_pane_id(self) -> str:
        return "%1"

    def run_in_new_pane(self, *, target, direction, percent, cmd, full=False):
        pane = next(self._panes)
        self.pane_launches.append(
            {
                "target": target,
                "direction": direction,
                "percent": percent,
                "cmd": cmd,
                "pane": pane,
                "full": full,
            }
        )
        return pane

    def set_option(self, name, value):
        self.options.append((name, value))

    def unset_option(self, name):
        self.unset_options.append(name)

    def pipe_pane(self, *, pane: str, output) -> None:
        self.pipe_pane_calls.append({"pane": pane, "output": output})


class _RestartSession:
    def __init__(self, *, options=None, existing=("%1", "%2", "%3"), active="%3"):
        self.options = dict(options or {})
        self.existing = set(existing)
        self.active = active
        self.sets: list[tuple[str, str]] = []
        self.unsets: list[str] = []
        self.respawns: list[tuple[str, str]] = []
        self.launches: list[dict[str, object]] = []
        self.selected: list[str] = []
        self.messages: list[str] = []
        self.kills: list[str] = []

    def get_option(self, name):
        return self.options.get(name, "")

    def set_option(self, name, value):
        self.options[name] = value
        self.sets.append((name, value))

    def unset_option(self, name):
        self.options.pop(name, None)
        self.unsets.append(name)

    def current_pane_id(self):
        return self.active

    def pane_exists(self, pane):
        return pane in self.existing

    def respawn_pane(self, *, pane, cmd):
        self.respawns.append((pane, cmd))

    def kill_pane(self, pane):
        self.kills.append(pane)
        self.existing.discard(pane)

    def run_in_new_pane(self, *, target, direction, percent, cmd, full=False):
        pane = "%4"
        self.existing.add(pane)
        self.launches.append(
            {"target": target, "direction": direction, "percent": percent, "cmd": cmd, "pane": pane, "full": full}
        )
        return pane

    def select_pane(self, target):
        self.selected.append(target)

    def display_message(self, message):
        self.messages.append(message)

    def pipe_pane(self, *, pane: str, output) -> None:
        pass


class _FakeContainer(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass

    def remove_volume(self, name: str) -> None:
        pass


class _DuContainer(_FakeContainer):
    def __init__(self, output="8192\t/ksrc/linux-6.6.30-volume\n", *, fail=False):
        self.output = output
        self.fail = fail
        self.runs = []
        self.execs = []
        self.stopped = []

    def run_detached(self, image, **kwargs):
        handle = SimpleNamespace(id="du-helper")
        self.runs.append({"image": image, **kwargs})
        return handle

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if self.fail:
            raise RuntimeError("du unavailable")
        return SimpleNamespace(exit_code=0, output=self.output)

    def stop(self, container):
        self.stopped.append(container.id)


# ---------------------------------------------------------------------------
# Pipeline stage-order tests (migrated + updated for new stages)
# ---------------------------------------------------------------------------


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == [
        "download",
        "unpack",
        "build",
        "cache-eviction",
        "profile-verification",
        "rootfs",
        "export",
        "module-build",
        "debuggee",
        "debugger",
    ]


def test_pipeline_has_module_build_before_debuggee(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert "module-build" in names
    assert names.index("module-build") < names.index("debuggee")


def test_debuggee_stage_has_workspace(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    dbge = next(s for s in pipe._stages if s.name == "debuggee")  # type: ignore[attr-defined]
    assert dbge._workspace == tmp_path  # type: ignore[attr-defined]


def test_summarize_cache_empty(tmp_path):
    assert summarize_cache(tmp_path) == ["(cache empty)"]


def test_summarize_cache_lists_build_and_rootfs(tmp_path):
    write_manifest(
        tmp_path,
        Manifest(
            kind="build", label="linux-6.6.30-aaaa", key="k", version="6.6.30", arch="arm64", storage_mode="volume"
        ),
    )
    rimg = tmp_path / "artifacts" / "rootfs" / "rootfs-arm64-bookworm-cccc.img"
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"x" * 2048)
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label="rootfs-arm64-bookworm-cccc",
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(rimg)},
        ),
    )
    lines = summarize_cache(tmp_path)
    joined = "\n".join(lines)
    assert "linux-6.6.30-aaaa" in joined and "6.6.30" in joined
    assert "rootfs-arm64-bookworm-cccc" in joined
    assert "build" in joined and "rootfs" in joined


def test_summarize_cache_uses_bind_build_image_host_size(tmp_path):
    image = tmp_path / "artifacts" / "ksrc" / "linux-6.6.30-bind" / "arch" / "arm64" / "boot" / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 4096)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label="linux-6.6.30-bind",
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="bind",
            paths={"image_host": str(image)},
        ),
    )
    assert "4096" in "\n".join(summarize_cache(tmp_path))


def test_summarize_cache_preserves_legacy_volume_image_size_fallback(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume"),
    )
    assert "1024" in "\n".join(summarize_cache(tmp_path))


def test_summarize_cache_uses_volume_tree_du_when_container_available(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={"kernel_root": f"/ksrc/{label}", "image_host": str(image)},
        ),
    )
    container = _DuContainer(output=f"8192\t/ksrc/{label}\n")
    joined = "\n".join(summarize_cache(tmp_path, container=container))
    assert "8192" in joined
    assert "1024" not in joined
    assert container.runs[0]["volumes"]["likedbg_ksrc"]["bind"] == "/ksrc"
    assert container.runs[0]["volumes"]["likedbg_ksrc"]["mode"] == "ro"
    assert container.execs == [f"du -sb /ksrc/{label}"]
    assert container.stopped == ["du-helper"]


def test_summarize_cache_falls_back_when_volume_du_fails(tmp_path):
    label = "linux-6.6.30-volume"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 1024)
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={"kernel_root": f"/ksrc/{label}", "image_host": str(image)},
        ),
    )
    assert "1024" in "\n".join(summarize_cache(tmp_path, container=_DuContainer(fail=True)))


def test_summarize_cache_shows_shared_source_refcount(tmp_path):
    srckey = "shared-src-key"
    src_label = "linux-6.6.30-gef-deadbeef"
    write_manifest(
        tmp_path,
        Manifest(kind="source", label=src_label, key=srckey, version="6.6.30", arch=""),
    )
    for label in ("linux-6.6.30-aaaa", "linux-6.6.30-bbbb"):
        write_manifest(
            tmp_path,
            Manifest(
                kind="build",
                label=label,
                key=label,
                version="6.6.30",
                arch="arm64",
                srckey=srckey,
                storage_mode="volume",
            ),
        )
    joined = "\n".join(summarize_cache(tmp_path))
    assert "shared sources:" in joined
    assert src_label in joined
    assert "refcount=2" in joined


def test_summarize_cache_uses_stamped_size_bytes_and_shows_last_used(tmp_path):
    """Verify --list uses stamped size_bytes + shows last_used WITHOUT calling du."""
    label = "linux-6.6.30-stamped"
    last_used_str = "2026-07-10T12:34:56+00:00"

    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            size_bytes=123456789,
            last_used=last_used_str,
            paths={"kernel_root": f"/ksrc/{label}", "image_host": "/path/to/image"},
        ),
    )

    # Use container that would fail if du were called
    container = _DuContainer(fail=True)

    joined = "\n".join(summarize_cache(tmp_path, container=container))

    # Should show the stamped size (no du call)
    assert "123456789" in joined

    # Should show last_used (at least the date part)
    assert "2026-07-10" in joined


def test_summarize_cache_fallback_on_legacy_zero_size_bytes(tmp_path):
    """Legacy manifests with size_bytes==0 should still use du fallback."""
    label = "linux-6.6.30-legacy"
    image = tmp_path / "artifacts" / label / "Image"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"x" * 2048)

    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            size_bytes=0,  # Legacy: zero indicates not yet stamped
            paths={"kernel_root": f"/ksrc/{label}", "image_host": str(image)},
        ),
    )

    # With size_bytes==0, should fall back to _artifact_size (checking Image file)
    joined = "\n".join(summarize_cache(tmp_path, container=None))
    assert "2048" in joined


def test_summarize_cache_source_uses_stamped_size_bytes(tmp_path):
    """Source manifests with size_bytes should use that instead of du."""
    srckey = "shared-src-key"
    src_label = "linux-6.6.30-gef-deadbeef"

    write_manifest(
        tmp_path,
        Manifest(
            kind="source",
            label=src_label,
            key=srckey,
            version="6.6.30",
            arch="",
            size_bytes=987654321,
        ),
    )

    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label="linux-6.6.30-aaaa",
            key="k",
            version="6.6.30",
            arch="arm64",
            srckey=srckey,
            storage_mode="volume",
        ),
    )

    # Use container that would fail if du were called
    container = _DuContainer(fail=True)

    joined = "\n".join(summarize_cache(tmp_path, container=container))

    # Should show the stamped size without calling du
    assert "987654321" in joined
    assert "shared sources:" in joined


def test_cmd_clean_unknown_label_raises(tmp_path):
    with pytest.raises(CacheError) as exc:
        cmd_clean(_FakeContainer(), tmp_path, label="nope", clean_all=False)
    assert "start_kgdb --list" in (exc.value.remedy or "")


def test_cmd_clean_all_removes_every_manifest(tmp_path):
    write_manifest(
        tmp_path,
        Manifest(
            kind="build", label="linux-6.6.30-aaaa", key="k", version="6.6.30", arch="arm64", storage_mode="volume"
        ),
    )
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label="rootfs-arm64-bookworm-cccc",
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(tmp_path / "gone.img")},
        ),
    )
    rc = cmd_clean(_FakeContainer(), tmp_path, label=None, clean_all=True)
    assert rc == 0
    assert cache.list_manifests(tmp_path, "build") == []
    assert cache.list_manifests(tmp_path, "rootfs") == []


def _write_shared_source_and_builds(tmp_path, *, srckey: str, src_label: str, labels: tuple[str, ...]):
    write_manifest(
        tmp_path,
        Manifest(kind="source", label=src_label, key=srckey, version="6.6.30", arch=""),
    )
    for label in labels:
        write_manifest(
            tmp_path,
            Manifest(
                kind="build",
                label=label,
                key=label,
                version="6.6.30",
                arch="arm64",
                srckey=srckey,
                storage_mode="volume",
            ),
        )


def test_cmd_clean_keeps_shared_source_until_last_referencing_build_removed(tmp_path, monkeypatch):
    srckey = "shared-src-key"
    src_label = "linux-6.6.30-gef-deadbeef"
    _write_shared_source_and_builds(
        tmp_path, srckey=srckey, src_label=src_label, labels=("linux-6.6.30-aaaa", "linux-6.6.30-bbbb")
    )
    removed_sources: list[str] = []
    orig_remove_source = cache.remove_source

    def recording_remove_source(container, workspace, label, *, storage_mode, volume=cache.KERNEL_VOLUME):
        removed_sources.append(label)
        orig_remove_source(container, workspace, label, storage_mode=storage_mode, volume=volume)

    monkeypatch.setattr(cache, "remove_source", recording_remove_source)

    # Removing build A: source is still referenced by build B (refcount 1) -> remove_source NOT called.
    rc = cmd_clean(_FakeContainer(), tmp_path, label="linux-6.6.30-aaaa", clean_all=False)
    assert rc == 0
    assert removed_sources == []
    assert cache.manifest_exists(tmp_path, "build", "linux-6.6.30-aaaa") is False
    assert cache.manifest_exists(tmp_path, "source", src_label) is True

    # Removing build B: source is now orphaned (refcount 0) -> remove_source IS called.
    rc = cmd_clean(_FakeContainer(), tmp_path, label="linux-6.6.30-bbbb", clean_all=False)
    assert rc == 0
    assert removed_sources == [src_label]
    assert cache.manifest_exists(tmp_path, "build", "linux-6.6.30-bbbb") is False
    assert cache.manifest_exists(tmp_path, "source", src_label) is False


def test_cmd_clean_all_removes_shared_source_too(tmp_path, monkeypatch):
    srckey = "shared-src-key"
    src_label = "linux-6.6.30-gef-deadbeef"
    _write_shared_source_and_builds(
        tmp_path, srckey=srckey, src_label=src_label, labels=("linux-6.6.30-aaaa", "linux-6.6.30-bbbb")
    )
    removed_sources: list[str] = []
    orig_remove_source = cache.remove_source

    def recording_remove_source(container, workspace, label, *, storage_mode, volume=cache.KERNEL_VOLUME):
        removed_sources.append(label)
        orig_remove_source(container, workspace, label, storage_mode=storage_mode, volume=volume)

    monkeypatch.setattr(cache, "remove_source", recording_remove_source)

    rc = cmd_clean(_FakeContainer(), tmp_path, label=None, clean_all=True)
    assert rc == 0
    assert removed_sources == [src_label]
    assert cache.list_manifests(tmp_path, "build") == []
    assert cache.list_manifests(tmp_path, "source") == []


def test_remove_orphaned_source_logs_removed_source(tmp_path):
    """Consolidation check: cli._remove_orphaned_source is now a thin wrapper around
    cache.drop_orphaned_source, but must still emit the "removed source" log line --clean relies on."""
    srckey = "shared-src-key"
    src_label = "linux-6.6.30-gef-deadbeef"
    write_manifest(tmp_path, Manifest(kind="source", label=src_label, key=srckey, version="6.6.30", arch=""))
    # `build`'s own manifest is intentionally NOT written: mirrors cmd_clean's real call order,
    # where cache.remove_cached already unlinked it before _remove_orphaned_source runs.
    build = Manifest(
        kind="build",
        label="linux-6.6.30-aaaa",
        key="k",
        version="6.6.30",
        arch="arm64",
        srckey=srckey,
        storage_mode="volume",
    )

    messages: list[str] = []
    handler_id = logger.add(messages.append, level="INFO")
    try:
        cli._remove_orphaned_source(_FakeContainer(), tmp_path, build)
    finally:
        logger.remove(handler_id)

    assert any(f"removed source {src_label}" in m for m in messages)
    assert cache.manifest_exists(tmp_path, "source", src_label) is False


def test_build_use_pipeline_includes_rootfs_before_launch(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    session = _FakeSession()
    pipe = build_use_pipeline(
        _FakeContainer(),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        gdb_mount_source="likedbg_ksrc",
        rootfs_recipe=rootfs_recipe(settings),
        module_env={},
        recorder=None,
    )
    assert [s.name for s in pipe._stages] == [  # type: ignore[attr-defined]
        "profile-verification",
        "rootfs",
        "export",
        "module-build",
        "debuggee",
        "debugger",
    ]


def _make_cmd_use_project(tmp_path: Path) -> None:
    """Create configs/default.toml so load_config succeeds in cmd_use tests."""
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "profiles").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.toml").write_text(
        '[source]\nkind="mmp"\nvalue="6.6.30"\n[general]\narch="arm64"\n'
    )
    (tmp_path / "configs" / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
    )


def test_cmd_use_builds_default_rootfs_when_manifest_is_missing(tmp_path, monkeypatch):
    _make_cmd_use_project(tmp_path)
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "debuggee": {"accel": "tcg", "network": "host"}})
    rr = rootfs_recipe(settings)
    target = rootfs_target(tmp_path, rr.label)

    class RootfsContainer(_FakeContainer):
        def __init__(self):
            super().__init__()
            self.rootfs_runs = []

        def run_detached(self, image, **kwargs):
            self.rootfs_runs.append({"image": image, **kwargs})
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"img")
            return SimpleNamespace(id="rootfs", logs=lambda **k: iter([]))

    label = "linux-6.6.30-bind"
    kernel_image = tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot" / "Image"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="bind",
            paths={
                "kernel_root": f"/ksrc/{label}",
                "gdb_vmlinux": f"/ksrc/{label}/vmlinux",
                "image_host": str(kernel_image),
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
                "gdb_mount_source": str(tmp_path / "artifacts" / "ksrc"),
            },
        ),
    )
    container = RootfsContainer()
    # Monkeypatch load_config so it returns a ConfigResolution with the right settings.
    # We also patch HostProfile.detect, _ensure_images, add_run_logfile, and RunRecorder.start.
    from likedbg.config import load_config as real_load_config

    def fake_load_config(workspace, *, scenario=None, cli_overrides=None):
        cr = real_load_config(workspace, scenario=scenario, cli_overrides={"general": {"arch": "arm64"}})
        return cr

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host("bind")))
    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: None)
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: (
                _FakeRecorder(workspace)
            )
        ),
    )

    session = _FakeSession()
    assert cli.cmd_use(container, session, tmp_path, custom_ini=None, label=label, rootfs_label=None) == 0
    rerun = json.loads(dict(session.options)["@likedbg_rerun_request"])
    assert rerun["kind"] == "use"
    assert rerun["use_label"] == label
    assert cache.manifest_exists(tmp_path, "rootfs", rr.label)
    assert target.read_bytes() == b"img"
    # ProfileVerificationStage also calls run_detached (legacy fallback, BASE_IMAGE).
    # Assert privileged=True on the SPECIFIC rootfs-build run (image == ROOTFS_IMAGE).
    rootfs_build_runs = [r for r in container.rootfs_runs if r["image"] == cli.ROOTFS_IMAGE]
    assert len(rootfs_build_runs) == 1, "expected exactly one rootfs-build container run"
    assert rootfs_build_runs[0]["privileged"] is True


def test_cmd_use_ensures_images_after_host_detection(tmp_path, monkeypatch):
    _make_cmd_use_project(tmp_path)
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    rr = rootfs_recipe(settings)
    rimg = rootfs_target(tmp_path, rr.label)
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=rr.label,
            key=rr.key,
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(rimg)},
        ),
    )
    label = "linux-6.6.30-volume"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={
                "kernel_root": f"/ksrc/{label}",
                "gdb_vmlinux": f"/ksrc/{label}/vmlinux",
                "image_host": str(tmp_path / "artifacts" / label / "Image"),
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
                "gdb_mount_source": "likedbg_ksrc",
            },
        ),
    )
    specs_seen = []
    from likedbg.config import load_config as real_load_config

    def fake_load_config(workspace, *, scenario=None, cli_overrides=None):
        return real_load_config(workspace, scenario=scenario, cli_overrides={"general": {"arch": "arm64"}})

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host("volume")))
    monkeypatch.setattr(
        cli,
        "_ensure_images",
        lambda container, workspace, *, specs: specs_seen.append(tuple(s.tag for s in specs)),
    )
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: (
                _FakeRecorder(workspace)
            )
        ),
    )

    assert cli.cmd_use(_FakeContainer(), _FakeSession(), tmp_path, custom_ini=None, label=label, rootfs_label=None) == 0
    assert specs_seen == [tuple(s.tag for s in cli.images.required_for_use(_host("volume")))]


class _FakeRecorder:
    """Minimal RunRecorder stand-in for pipeline tests — mirrors the public RunRecorder API."""

    def __init__(self, workspace: Path) -> None:
        self.run_dir = workspace / "artifacts" / "runs" / "fake"
        logs = self.run_dir / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        self.likedbg_log = logs / "likedbg.log"
        self.debuggee_pane_log = logs / "debuggee-pane.log"
        self.debugger_pane_log = logs / "debugger-pane.log"
        self.console_raw = logs / "console.raw"
        self.crash_dir = workspace / "artifacts" / "runs" / "fake" / "crash"

    def add_warning(self, code: str, message: str) -> None:
        pass

    def record_profile_verification(self, verification: object) -> None:
        pass

    def record_kernel_paths(self, *, config, system_map, vmlinux, image) -> None:
        pass

    def set_status(self, status: str, *, message: str | None = None) -> None:
        pass

    def record_command(self, kind: str, *, shell: str, argv: list) -> None:
        pass


def test_pipeline_launches_process_panes_and_stores_session_options(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    recorder = _FakeRecorder(tmp_path)
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=recorder,
    )
    ctx = PipelineContext(settings=settings, host=_host("volume"), build_label=br.label, rootfs_label=rr.label)
    ctx.kernel_image = tmp_path / "artifacts" / br.label / "Image"
    ctx.rootfs_image = tmp_path / "artifacts" / "rootfs.img"
    ctx.vmlinux = tmp_path / "artifacts" / br.label / "vmlinux"

    # Run only the debuggee and debugger stages (indices -2 and -1)
    pipe._stages[-2].run(ctx)  # type: ignore[attr-defined]
    pipe._stages[-1].run(ctx)  # type: ignore[attr-defined]

    # Debuggee (QEMU) splits below the host CLI (%1) in the left column.
    assert session.pane_launches[0]["target"] == "%1"
    assert session.pane_launches[0]["direction"] == "v"
    assert session.pane_launches[0]["percent"] == 50
    assert session.pane_launches[0]["full"] is False
    # Debugger takes the full-height right column (-f) off the host-CLI anchor.
    assert session.pane_launches[1]["target"] == "%1"
    assert session.pane_launches[1]["direction"] == "h"
    assert session.pane_launches[1]["percent"] == 62
    assert session.pane_launches[1]["full"] is True
    assert session.unset_options == [
        "@likedbg_restart_in_progress",
        "@likedbg_rerun_request",
        "@likedbg_active_run_dir",
        "@likedbg_debuggee_cmd",
        "@likedbg_debugger_cmd",
        "@likedbg_debuggee_pane",
        "@likedbg_debugger_pane",
        "@likedbg_debuggee_pane_log",
    ]
    assert session.options[0:2] == [
        ("@likedbg_workspace", str(tmp_path)),
        ("@likedbg_base_pane_id", "%1"),
    ]
    options = dict(session.options)
    assert options["@likedbg_debuggee_cmd"] == session.pane_launches[0]["cmd"]
    assert options["@likedbg_debugger_cmd"] == session.pane_launches[1]["cmd"]
    assert options["@likedbg_debuggee_pane"] == "%2"
    assert options["@likedbg_debugger_pane"] == "%3"
    # New: transcript capture options set when recorder is provided
    assert options["@likedbg_debuggee_pane_log"] == str(recorder.debuggee_pane_log)
    assert any(c["pane"] == "%2" for c in session.pipe_pane_calls), "pipe_pane should have been called for debuggee"
    assert any(c["pane"] == "%3" for c in session.pipe_pane_calls), "pipe_pane should have been called for debugger"


def _fk(tmp_path):
    """Minimal ForeignKernel fixture — mirrors test_cli_foreign.py's helper."""
    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(b"\x7fELF")
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    return ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )


def test_build_use_pipeline_mounts_exploit_share_when_supplied(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    session = _FakeSession()
    pipe = build_use_pipeline(
        _FakeContainer(),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        gdb_mount_source="likedbg_ksrc",
        rootfs_recipe=rootfs_recipe(settings),
        module_env={},
        recorder=None,
        exploit_share=tmp_path / "exploit",
    )
    dbge = next(s for s in pipe._stages if s.name == "debuggee")  # type: ignore[attr-defined]
    dbg = next(s for s in pipe._stages if s.name == "debugger")  # type: ignore[attr-defined]
    dbge._launch("qemu-cmd")  # type: ignore[attr-defined]
    dbg._run_gdb(["gdb"])  # type: ignore[attr-defined]
    assert f"-v {tmp_path / 'exploit'}:/exploit:ro" in session.pane_launches[1]["cmd"]
    assert dbg._modules_gdb == "/exploit/modules.gdb"  # type: ignore[attr-defined]


def test_build_use_pipeline_no_modules_gdb_without_exploit_share(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    session = _FakeSession()
    pipe = build_use_pipeline(
        _FakeContainer(),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        gdb_mount_source="likedbg_ksrc",
        rootfs_recipe=rootfs_recipe(settings),
        module_env={},
        recorder=None,
    )
    dbg = next(s for s in pipe._stages if s.name == "debugger")  # type: ignore[attr-defined]
    assert dbg._modules_gdb is None  # type: ignore[attr-defined]


def test_build_foreign_pipeline_never_mounts_exploit_share(tmp_path):
    session = _FakeSession()
    pipe = build_foreign_pipeline(
        _FakeContainer(),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        foreign=_fk(tmp_path),
        exploit=None,
        qemu_extra=(),
        gdb_mount_source=str(tmp_path),
        out_dir=tmp_path / "stage",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        musl_image="like_musl:latest",
        recorder=None,
    )
    dbge = next(s for s in pipe._stages if s.name == "debuggee")  # type: ignore[attr-defined]
    dbg = next(s for s in pipe._stages if s.name == "debugger")  # type: ignore[attr-defined]
    dbge._launch("qemu-cmd")  # type: ignore[attr-defined]
    dbg._run_gdb(["gdb"])  # type: ignore[attr-defined]
    assert ":/exploit:ro" not in session.pane_launches[1]["cmd"]
    assert dbg._modules_gdb is None  # type: ignore[attr-defined]  # ADR-0010: no share, no hook


# ---------------------------------------------------------------------------
# resolve_for_run tests
# ---------------------------------------------------------------------------


def test_resolve_for_run_unknown_profile_raises_and_creates_no_run_dir(tmp_path, monkeypatch):
    """Unknown profile must raise ConfigError BEFORE any run dir is created."""
    _make_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError):
        cli.resolve_for_run(tmp_path, profile_arg="asan", scenario=None, cli_overrides=None)
    # The run directory must NOT have been created.
    assert not (tmp_path / "artifacts" / "runs").exists()


def test_resolve_for_run_exploit_dev_resolves(tmp_path, monkeypatch):
    """Default exploit-dev profile resolves when a configs/profiles/exploit-dev.toml is present."""
    _make_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    cfg, host, rr = cli.resolve_for_run(tmp_path, profile_arg="exploit-dev", scenario=None, cli_overrides=None)
    assert "exploit-dev" in rr.profiles.names
    # No run dir should exist — resolve_for_run itself never creates one.
    assert not (tmp_path / "artifacts" / "runs").exists()


# ---------------------------------------------------------------------------
# Restart tests
# ---------------------------------------------------------------------------


def _restart_options():
    return {
        "@likedbg_workspace": "/ws",
        "@likedbg_base_pane_id": "%1",
        "@likedbg_debuggee_cmd": "qemu-system-aarch64 -S",
        "@likedbg_debuggee_pane": "%2",
    }


def test_restart_debuggee_respawns_existing_pane_in_place():
    session = _RestartSession(options=_restart_options())
    assert cli.cmd_restart_debuggee(session) == 0  # type: ignore[arg-type]
    assert session.sets[0] == ("@likedbg_restart_in_progress", "1")
    assert session.respawns == [("%2", "qemu-system-aarch64 -S")]
    assert session.launches == []
    assert session.selected == ["%3"]
    assert session.messages == [
        "LIKE-DBG Debuggee restarted; in GDB run likedbg-reconnect, not target remote localhost"
    ]
    assert "@likedbg_restart_in_progress" in session.unsets
    assert session.options["@likedbg_debuggee_pane"] == "%2"


def test_restart_debuggee_recreates_when_debuggee_pane_stale():
    session = _RestartSession(options=_restart_options(), existing=("%1", "%3"))
    assert cli.cmd_restart_debuggee(session) == 0  # type: ignore[arg-type]
    assert session.respawns == []
    assert session.launches == [
        {
            "target": "%1",
            "direction": "v",
            "percent": 50,
            "cmd": "qemu-system-aarch64 -S",
            "pane": "%4",
            "full": False,
        }
    ]
    assert session.options["@likedbg_debuggee_pane"] == "%4"
    assert session.selected == ["%3"]
    assert session.messages == [
        "LIKE-DBG Debuggee restarted; in GDB run likedbg-reconnect, not target remote localhost"
    ]


def test_restart_debuggee_missing_command_or_workspace_raises_remedy():
    for missing in ("@likedbg_workspace", "@likedbg_debuggee_cmd"):
        options = _restart_options()
        options.pop(missing)
        with pytest.raises(SessionError) as exc:
            cli.cmd_restart_debuggee(_RestartSession(options=options))  # type: ignore[arg-type]
        assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_clears_lock_on_post_acquire_failure():
    options = _restart_options()
    options.pop("@likedbg_workspace")
    session = _RestartSession(options=options)
    with pytest.raises(SessionError):
        cli.cmd_restart_debuggee(session)  # type: ignore[arg-type]
    assert session.unsets[-1] == "@likedbg_restart_in_progress"
    assert "@likedbg_restart_in_progress" not in session.options


def test_restart_debuggee_missing_base_only_fatal_for_recreate():
    existing_debuggee = _RestartSession(options=_restart_options(), existing=("%2", "%3"))
    assert cli.cmd_restart_debuggee(existing_debuggee) == 0  # type: ignore[arg-type]

    missing_base = _RestartSession(options=_restart_options(), existing=("%3",))
    with pytest.raises(SessionError) as exc:
        cli.cmd_restart_debuggee(missing_base)  # type: ignore[arg-type]
    assert "fresh Debugging session" in (exc.value.remedy or "")


def test_restart_debuggee_lock_prevents_double_tap():
    options = _restart_options()
    options["@likedbg_restart_in_progress"] = "1"
    session = _RestartSession(options=options)
    with pytest.raises(SessionError) as exc:
        cli.cmd_restart_debuggee(session)  # type: ignore[arg-type]
    assert "already in progress" in str(exc.value)
    assert session.respawns == []
    assert session.launches == []
    assert session.unsets == []


def test_main_restart_bypasses_config_and_docker(monkeypatch):
    restarted = []
    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: pytest.fail("load_config should not run"))
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: pytest.fail("docker should not run"))
    monkeypatch.setattr(cli, "cmd_restart_debuggee", lambda session: restarted.append(session) or 0)
    assert cli.main(["--restart-debuggee"]) == 0
    assert len(restarted) == 1


def test_main_restart_failure_displays_tmux_message(monkeypatch):
    created = []

    class FakeSession(_RestartSession):
        def __init__(self, name):
            super().__init__()
            self.name = name
            created.append(self)

    def fail_restart(session):
        raise SessionError("missing @likedbg_debuggee_cmd", remedy="start fresh")

    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "Session", FakeSession)
    monkeypatch.setattr(cli, "cmd_restart_debuggee", fail_restart)
    assert cli.main(["--restart-debuggee"]) == 1
    assert created[0].messages == ["LIKE-DBG restart failed: missing @likedbg_debuggee_cmd"]


def test_main_restart_requires_tmux(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: pytest.fail("load_config should not run"))
    assert cli.main(["--restart-debuggee"]) == 2


def test_rerun_stops_managed_panes_then_reenters_foreign_launch_dispatch(tmp_path, monkeypatch):
    _make_project(tmp_path)
    scenario = tmp_path / "pawnyable.toml"
    scenario.write_text('[foreign]\nimage = "kernel"\n')
    request = json.dumps(
        {
            "version": 1,
            "workspace": str(tmp_path.resolve()),
            "kind": "foreign",
            "scenario": str(scenario.resolve()),
            "profile_arg": "",
        }
    )
    session = _RestartSession(
        options={
            "@likedbg_rerun_request": request,
            "@likedbg_base_pane_id": "%1",
            "@likedbg_debuggee_pane": "%2",
            "@likedbg_debugger_pane": "%3",
        }
    )
    captured = {}
    monkeypatch.setattr(cli.docker_env, "make_client", lambda _host: object())
    monkeypatch.setattr(cli, "main", lambda argv: captured.update({"argv": argv}) or 0)
    assert cli.cmd_rerun(session, tmp_path) == 0  # type: ignore[arg-type]
    assert session.kills == ["%3", "%2"]
    assert captured == {"argv": ["--config", str(scenario.resolve())]}


def test_rerun_request_round_trips_as_absolute_session_state(tmp_path):
    scenario = tmp_path / "pawnyable.toml"
    scenario.write_text("")
    session = _RestartSession()
    cli._save_rerun_request(  # noqa: SLF001 - exercise the tmux-state seam directly
        session,
        workspace=tmp_path,
        kind="foreign",
        scenario=scenario,
        profile_arg="exploit-dev",
        run_dir=tmp_path / "run",
    )
    request = cli._load_rerun_request(session, workspace=tmp_path)  # noqa: SLF001
    assert request.kind == "foreign"
    assert request.scenario == scenario.resolve()
    assert request.profile_arg == "exploit-dev"


def test_save_rerun_request_persists_no_force_rebuild_key(tmp_path):
    """force_rebuild is no longer session state (Task 5): the persisted request must not carry a
    force_rebuild key at all, so a stored session can never replay a stale force."""
    session = _RestartSession()
    cli._save_rerun_request(  # noqa: SLF001 - exercise the tmux-state seam directly
        session,
        workspace=tmp_path,
        kind="normal",
        scenario=None,
        profile_arg="",
        run_dir=tmp_path / "run",
    )
    data = json.loads(session.options[cli._RERUN_OPTION])  # noqa: SLF001
    assert "force_rebuild" not in data


def test_load_rerun_request_tolerates_stale_force_rebuild_key(tmp_path):
    """Upgrade tolerance: a live tmux session started before this change may still have a stored
    request with a stale force_rebuild key. _load_rerun_request reads fields individually rather
    than splatting the dict, so the extra key must be silently ignored, not rejected as invalid
    active re-run state -- stranding an in-flight session on upgrade would be worse than the bug
    this fixes."""
    request = json.dumps(
        {
            "version": 1,
            "workspace": str(tmp_path.resolve()),
            "kind": "normal",
            "scenario": "",
            "profile_arg": "",
            "force_rebuild": True,
        }
    )
    session = _RestartSession(options={"@likedbg_rerun_request": request})
    loaded = cli._load_rerun_request(session, workspace=tmp_path)  # noqa: SLF001
    assert loaded.kind == "normal"
    assert not hasattr(loaded, "force_rebuild")


def test_rerun_foreign_preflights_before_killing_panes(tmp_path):
    _make_project(tmp_path)
    scenario = tmp_path / "not-foreign.toml"
    scenario.write_text("[debuggee]\nmemory_mib = 64\n")
    request = json.dumps(
        {
            "version": 1,
            "workspace": str(tmp_path.resolve()),
            "kind": "foreign",
            "scenario": str(scenario.resolve()),
            "profile_arg": "",
        }
    )
    session = _RestartSession(
        options={
            "@likedbg_rerun_request": request,
            "@likedbg_base_pane_id": "%1",
            "@likedbg_debuggee_pane": "%2",
            "@likedbg_debugger_pane": "%3",
        }
    )
    with pytest.raises(SessionError, match="no longer a foreign"):
        cli.cmd_rerun(session, tmp_path)  # type: ignore[arg-type]
    assert session.kills == []


def test_main_rerun_bypasses_normal_config_and_docker_setup(monkeypatch):
    rerun = []
    monkeypatch.setenv("TMUX", "/tmp/tmux")
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: pytest.fail("normal config flow should not run"))
    monkeypatch.setattr(
        cli, "cmd_rerun", lambda session, workspace, *, force_rebuild=False: rerun.append((session, workspace)) or 0
    )
    assert cli.main(["--re-run"]) == 0
    assert len(rerun) == 1


def test_rerun_argv_reconstructs_normal_and_use_selectors(tmp_path):
    normal = cli.RerunRequest(kind="normal", scenario=None, profile_arg="kasan")
    use = cli.RerunRequest(
        kind="use", scenario=tmp_path / "scenario.toml", profile_arg="", use_label="linux-foo", rootfs_label="rootfs-bar"
    )
    assert cli._rerun_argv(normal, force_rebuild=True) == ["--profile", "kasan", "--force-rebuild"]  # noqa: SLF001
    # kind="use" wins over force_rebuild: a cached build selected by label has no rebuild to force.
    assert cli._rerun_argv(use, force_rebuild=True) == [  # noqa: SLF001
        "--config",
        str(tmp_path / "scenario.toml"),
        "--use",
        "linux-foo",
        "--rootfs",
        "rootfs-bar",
    ]


def test_rerun_argv_normal_plain_rerun_omits_force_rebuild(tmp_path):
    """force_rebuild is an argument to _rerun_argv now, not a field read off the request -- a plain
    --re-run (force_rebuild=False) must not force, regardless of what an earlier boot did."""
    request = cli.RerunRequest(kind="normal", scenario=None, profile_arg="kasan")
    assert cli._rerun_argv(request, force_rebuild=False) == ["--profile", "kasan"]  # noqa: SLF001


def test_rerun_argv_foreign_plain_rerun_omits_force_rebuild(tmp_path):
    """Reuse on plain --re-run is the entire reason --force-rebuild threading exists: rebooting
    to flip a guest mitigation must not pay for a repack. A plain --re-run (force_rebuild=False)
    must replay without it, even for a foreign RerunRequest."""
    request = cli.RerunRequest(kind="foreign", scenario=tmp_path / "scenario.toml", profile_arg="")
    assert cli._rerun_argv(request, force_rebuild=False) == ["--config", str(tmp_path / "scenario.toml")]  # noqa: SLF001


def test_rerun_argv_foreign_force_rebuild_composes_with_rerun(tmp_path):
    """The other direction: --re-run --force-rebuild must replay with the flag -- it now comes from
    the argument typed on this re-run, not anything persisted on the request."""
    request = cli.RerunRequest(kind="foreign", scenario=tmp_path / "scenario.toml", profile_arg="")
    assert cli._rerun_argv(request, force_rebuild=True) == [  # noqa: SLF001
        "--config",
        str(tmp_path / "scenario.toml"),
        "--force-rebuild",
    ]


def test_main_build_images_is_docker_only_and_invokes_build_images(monkeypatch):
    built = []
    monkeypatch.setattr(
        cli, "load_config", lambda *a, **k: ConfigResolution(settings=Settings(), provenance={}, _ordered_layers=())
    )
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.images, "build_images", lambda container, workspace, *a, **k: built.append(True))
    monkeypatch.delenv("TMUX", raising=False)  # build-images must NOT require tmux

    assert cli.main(["--build-images"]) == 0
    assert built == [True]


def test_ensure_images_helper_warns_each_stale_tag(monkeypatch):
    monkeypatch.setattr(cli.images, "ensure_current", lambda container, workspace, specs: ["like_rootfs:latest"])
    msgs = []
    monkeypatch.setattr(cli.logger, "warning", lambda msg: msgs.append(msg))
    cli._ensure_images(object(), object(), specs=())
    assert len(msgs) == 1
    assert "like_rootfs:latest" in msgs[0]
    assert "--build-images" in msgs[0]


def test_main_configures_stderr_always_but_logfile_only_for_runs(monkeypatch):
    calls = {"stderr": 0, "logfile": 0}
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.logsetup, "configure_stderr", lambda **k: calls.__setitem__("stderr", calls["stderr"] + 1))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda ws: calls.__setitem__("logfile", calls["logfile"] + 1))
    monkeypatch.setattr(cli, "summarize_cache", lambda ws, **kwargs: ["(cache empty)"])

    assert cli.main(["--list"]) == 0
    assert calls["stderr"] == 1  # configure_stderr runs for every invocation
    assert calls["logfile"] == 0  # --list writes no run log file


# ---------------------------------------------------------------------------
# explain_config tests
# ---------------------------------------------------------------------------


def _make_explain_project(tmp_path: Path) -> None:
    """Minimal project layout for explain_config tests."""
    cfgs = tmp_path / "configs"
    (cfgs / "fragments").mkdir(parents=True)
    (cfgs / "profiles").mkdir(parents=True)
    (cfgs / "default.toml").write_text('[source]\nkind="mmp"\nvalue="6.6.30"\n')
    (cfgs / "fragments" / "generic.config").write_text("")
    (cfgs / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\nfragments=["configs/fragments/generic.config"]\n'
    )


def test_explain_config_json_no_run_dir(tmp_path: Path, monkeypatch) -> None:
    _make_explain_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    out = cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="json")
    data = json.loads(out)
    assert data["profiles"]["resolved"] == ["exploit-dev"]
    assert data["target_arch"] in ("x86_64", "arm64")
    assert not (tmp_path / "artifacts" / "runs").exists()


def test_explain_config_marks_expectations_pending(tmp_path: Path, monkeypatch) -> None:
    _make_explain_project(tmp_path)
    (tmp_path / "configs" / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
        'fragments=["configs/fragments/generic.config"]\n'
        '[[expect]]\nsymbol="CONFIG_GDB_SCRIPTS"\nvalue="y"\nseverity="soft"\n'
    )
    monkeypatch.chdir(tmp_path)
    data = json.loads(cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="json"))
    assert data["expected_config"][0]["status"] == "pending-build"


def test_explain_config_text_returns_string(tmp_path: Path, monkeypatch) -> None:
    _make_explain_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    out = cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="text")
    assert isinstance(out, str)
    assert "exploit-dev" in out


def test_explain_config_json_schema_version(tmp_path: Path, monkeypatch) -> None:
    _make_explain_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    data = json.loads(cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="json"))
    assert data["schema_version"] == 1


def test_explain_config_surfaces_extra_fragments_and_patch_dirs(tmp_path: Path, monkeypatch) -> None:
    """--explain-config must show the user's [build] extra_fragments + patch_dirs, not only profile fragments."""
    _make_explain_project(tmp_path)
    (tmp_path / "configs" / "default.toml").write_text(
        '[source]\nkind="mmp"\nvalue="6.6.30"\n'
        '[build]\nextra_fragments=["configs/fragments/my-feature.config"]\npatch_dirs=["patches/my-fix"]\n'
    )
    monkeypatch.chdir(tmp_path)
    data = json.loads(cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="json"))
    assert data["extra_fragments"] == ["configs/fragments/my-feature.config"]
    assert data["patch_dirs"] == ["patches/my-fix"]
    text = cli.explain_config(tmp_path, profile_arg="exploit-dev", scenario=None, fmt="text")
    assert "configs/fragments/my-feature.config" in text and "patches/my-fix" in text


# ---------------------------------------------------------------------------
# FIX 1: patch_dirs wiring through build_pipeline
# ---------------------------------------------------------------------------


def test_build_pipeline_threads_patch_dirs_to_unpack_stage(tmp_path):
    """UnpackStage inside the built pipeline must receive the patch_dirs passed to build_pipeline
    (patches apply once against the shared source in Unpack, not per-build; BuildStage has no
    patch_dirs param at all, Task 8)."""
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    patch_dirs = ("patches/uaf", "patches/heap")
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        patch_dirs=patch_dirs,
        recorder=None,
    )
    unpack_stage = next(s for s in pipe._stages if s.name == "unpack")  # type: ignore[attr-defined]
    assert unpack_stage._patch_dirs == patch_dirs  # type: ignore[attr-defined]
    build_stage = next(s for s in pipe._stages if s.name == "build")
    assert not hasattr(build_stage, "_patch_dirs")  # dead param removed from BuildStage


def test_build_pipeline_passes_crash_config(tmp_path):
    """DebuggerStage inside the built pipeline must receive break_on_crash/crash_breakpoints."""
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
        break_on_crash=True,
        crash_breakpoints=("panic", "die"),
    )
    dbg = pipe._stages[-1]  # type: ignore[attr-defined]
    assert dbg._break_on_crash is True  # type: ignore[attr-defined]
    assert dbg._crash_breakpoints == ("panic", "die")  # type: ignore[attr-defined]


def test_build_pipeline_passes_modules_gdb_when_exploit_share_set(tmp_path):
    """DebuggerStage inside the built pipeline gets the in-container modules.gdb path when the run
    has a guest-backed exploit share (Task 5: A2 module-symbol stop-hook)."""
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
        exploit_share=tmp_path / "exploit",
    )
    dbg = pipe._stages[-1]  # type: ignore[attr-defined]
    assert dbg._modules_gdb == "/exploit/modules.gdb"  # type: ignore[attr-defined]


def test_build_pipeline_no_modules_gdb_without_exploit_share(tmp_path):
    """No exploit share -> no modules.gdb path -> build_gdb_args gets modules_gdb=None (no hook)."""
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    dbg = pipe._stages[-1]  # type: ignore[attr-defined]
    assert dbg._modules_gdb is None  # type: ignore[attr-defined]


def test_build_pipeline_defaults_patch_dirs_to_empty(tmp_path):
    """build_pipeline without patch_dirs defaults to () on UnpackStage (the sole consumer)."""
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = _FakeSession()
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()),
        session,  # type: ignore[arg-type]
        host=_host("volume"),
        workspace=tmp_path,
        kernel_volume="likedbg_ksrc",
        dl_dir=tmp_path / "kernels",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="gef",
        build_recipe=br,
        rootfs_recipe=rr,
        recorder=None,
    )
    unpack_stage = next(s for s in pipe._stages if s.name == "unpack")  # type: ignore[attr-defined]
    assert unpack_stage._patch_dirs == ()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# FIX 3: --use --profile threading through cmd_use
# ---------------------------------------------------------------------------


def _make_cmd_use_with_profile_project(tmp_path: Path) -> None:
    """Minimal project with two profiles: exploit-dev (base) and hardened (base)."""
    cfgs = tmp_path / "configs"
    (cfgs / "profiles").mkdir(parents=True, exist_ok=True)
    (cfgs / "fragments").mkdir(parents=True, exist_ok=True)
    (cfgs / "default.toml").write_text('[source]\nkind="mmp"\nvalue="6.6.30"\n[general]\narch="arm64"\n')
    (cfgs / "profiles" / "exploit-dev.toml").write_text('name="exploit-dev"\nkind="base"\ndescription="d"\n')
    (cfgs / "profiles" / "hardened.toml").write_text('name="hardened"\nkind="base"\ndescription="hardened"\n')


def test_cmd_use_threads_profile_arg_into_resolve_for_run(tmp_path, monkeypatch):
    """cmd_use with profile_arg="hardened" must resolve hardened, not the default exploit-dev."""
    _make_cmd_use_with_profile_project(tmp_path)
    resolved_profiles = []

    original_resolve = cli.resolve_for_run

    def capturing_resolve(workspace, *, profile_arg, scenario, cli_overrides):
        result = original_resolve(workspace, profile_arg=profile_arg, scenario=scenario, cli_overrides=cli_overrides)
        resolved_profiles.append(list(result[2].profiles.names))
        return result

    label = "linux-6.6.30-volume"
    write_manifest(
        tmp_path,
        Manifest(
            kind="build",
            label=label,
            key="k",
            version="6.6.30",
            arch="arm64",
            storage_mode="volume",
            paths={
                "kernel_root": f"/ksrc/{label}",
                "gdb_vmlinux": f"/ksrc/{label}/vmlinux",
                "image_host": str(tmp_path / "artifacts" / label / "Image"),
                "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image",
                "gdb_mount_source": "likedbg_ksrc",
            },
        ),
    )
    # Pre-build rootfs so cmd_use doesn't try to build it
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    rr = rootfs_recipe(settings)
    rimg = tmp_path / "artifacts" / "rootfs" / f"{rr.label}.img"
    rimg.parent.mkdir(parents=True, exist_ok=True)
    rimg.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=rr.label,
            key=rr.key,
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(rimg)},
        ),
    )

    from likedbg.config import load_config as real_load_config

    def fake_load_config(workspace, *, scenario=None, cli_overrides=None):
        return real_load_config(
            workspace, scenario=scenario, cli_overrides=cli_overrides or {"general": {"arch": "arm64"}}
        )

    monkeypatch.setattr(cli, "resolve_for_run", capturing_resolve)
    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host("volume")))
    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: None)
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: (
                _FakeRecorder(workspace)
            )
        ),
    )

    result = cli.cmd_use(
        _FakeContainer(),
        _FakeSession(),
        tmp_path,
        custom_ini=None,
        label=label,
        rootfs_label=None,
        profile_arg="hardened",
    )
    assert result == 0
    # The resolve call (which capturing_resolve intercepted) must have used "hardened"
    assert any("hardened" in names for names in resolved_profiles), (
        f"Expected 'hardened' in resolved profiles, got: {resolved_profiles}"
    )
    assert not any("exploit-dev" in names for names in resolved_profiles), (
        f"exploit-dev must not appear when profile_arg='hardened'; got: {resolved_profiles}"
    )


# ---------------------------------------------------------------------------
# --analyze-crash / cmd_analyze_crash
# ---------------------------------------------------------------------------


def test_cmd_analyze_crash_writes_report(tmp_path, capsys):
    run = tmp_path / "artifacts" / "runs" / "20260704T000000Z-linux-6.6.30-x"
    (run / "logs").mkdir(parents=True)
    (run / "crash").mkdir()
    (run / "logs" / "console.raw").write_text("[ 1.0] Kernel panic - not syncing: test\n")
    (run / "host.json").write_text(json.dumps({"target_arch": "x86_64"}))
    (run / "run.json").write_text(
        json.dumps({"status": "launched", "build_label": "linux-6.6.30-x", "status_history": []})
    )
    rc = cli.cmd_analyze_crash(tmp_path, run_id=run.name)
    assert rc == 0
    assert (run / "crash.json").is_file()
    assert "panic" in capsys.readouterr().out


def test_cmd_analyze_crash_no_crash(tmp_path, capsys):
    run = tmp_path / "artifacts" / "runs" / "r2"
    (run / "logs").mkdir(parents=True)
    (run / "logs" / "console.raw").write_text("[ 0.1] booting\n")
    (run / "host.json").write_text(json.dumps({"target_arch": "x86_64"}))
    (run / "run.json").write_text(json.dumps({"status": "launched", "build_label": "linux-6.6.30-x"}))
    assert cli.cmd_analyze_crash(tmp_path, run_id="r2") == 0
    assert "no crash detected" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# --run / cmd_run
# ---------------------------------------------------------------------------


def test_cmd_run_dispatches(tmp_path, monkeypatch, capsys):
    run = tmp_path / "artifacts" / "runs" / "r1"
    (run / "logs").mkdir(parents=True)
    (run / "exploit").mkdir()
    (run / "crash").mkdir()
    (run / "logs" / "console.raw").write_text("[ 0.1] booting\n")
    (run / "host.json").write_text(json.dumps({"target_arch": "x86_64"}))
    (run / "run.json").write_text(
        json.dumps(
            {
                "status": "launched",
                "build_label": "linux-6.6.30-x",
                "rootfs_label": "rootfs-x86_64-bookworm-abc",
                "guest": {
                    "ssh_host": "127.0.0.1",
                    "ssh_port": 2222,
                    "share_mount": "/mnt/exploit",
                    "share_dir": "exploit",
                },
            }
        )
    )
    reg = tmp_path / "artifacts" / "cache" / "rootfs"
    reg.mkdir(parents=True)
    (reg / "rootfs-x86_64-bookworm-abc.json").write_text(
        json.dumps(
            {
                "kind": "rootfs",
                "label": "rootfs-x86_64-bookworm-abc",
                "key": "k",
                "version": "",
                "arch": "x86_64",
                "paths": {
                    "image_host": "/w/artifacts/rootfs/rootfs.img",
                    "ssh_key": "/w/artifacts/rootfs/rootfs.img.id_ed25519",
                },
            }
        )
    )
    (tmp_path / "exploit").mkdir()
    poc = tmp_path / "exploit" / "poc"
    poc.write_text("#!/bin/sh\necho pwned\n")

    monkeypatch.setattr(guest, "wait_ready", lambda ep, **kw: True)
    monkeypatch.setattr(guest, "run", lambda ep, cmd, **kw: SimpleNamespace(rc=0, stdout="pwned\n", stderr=""))
    monkeypatch.setattr(guest, "push", lambda ep, local, remote, **kw: None)

    rc = cli.cmd_run(tmp_path, run_id="r1", exploit=str(poc), args="")
    assert rc == 0
    out = capsys.readouterr().out
    assert "pwned" in out
    assert (run / "exploit" / "poc.log").read_text().strip() == "pwned"


def test_clean_all_removes_zig_cache_volume(tmp_path, monkeypatch):
    from likedbg.constants import LIKEDBG_ZIG_CACHE_VOLUME

    removed: list[str] = []

    class _C:
        def remove_volume(self, name):
            removed.append(name)

    monkeypatch.setattr(cache, "list_manifests", lambda *a, **k: [])
    cmd_clean(_C(), tmp_path, label=None, clean_all=True)
    assert LIKEDBG_ZIG_CACHE_VOLUME in removed
