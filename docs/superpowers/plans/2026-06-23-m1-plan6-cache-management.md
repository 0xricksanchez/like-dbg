# M1 Plan 6 — Build Cache Management (`--list` / `--clean` / `--use`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the cache *management* surface to `start_kgdb` — list cached Kernel Builds and rootfs images, clean selected/all entries, and boot a cached build directly by label (`--use`) with zero rebuild.

**Architecture:** Extend `cache.py` with `list_manifests` (read all manifests of a kind) and `remove_cached` (delete an artifact's footprint + manifest, via an injected `ContainerService` for the in-volume tree). Add three thin CLI actions (`cmd_list`, `cmd_clean`, `cmd_use`) dispatched from `main`, plus a launch-only pipeline (`build_use_pipeline` = Export → Debuggee → Debugger) whose context is pre-populated from a build Manifest. `--use` honors the grilled precedence: the build Manifest's `arch` is authoritative (re-load settings with an arch override), runtime/debugger prefs come from the active config.

**Tech Stack:** Python 3.12, Pydantic, docker-py, argparse, tmux, `qemu-system-aarch64 -accel hvf`, `gdb-multiarch`+gef/pwndbg; uv/ruff/mypy.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-23-build-reuse-cache-design.md` §4.5 (CLI surface), §4.6 (errors). **Glossary:** `CONTEXT.md` (Kernel Build, Label, Manifest, Build Cache). **ADRs:** 0001/0002/0003.
- New code under `src/likedbg/`; tests under `tests/`; legacy flat `src/*.py` untouched (ruff `force-exclude`). `mypy --strict` clean over `src/likedbg`; `ruff check .` / `ruff format --check .` clean; line length 120. Tools via `uv run`.
- Errors are `LikeDbgError` subclasses with `remedy=`; side-effects behind the injected `ContainerService` seam. Unknown `--use`/`--clean`/`--rootfs` label → `CacheError` with a remedy that points at `--list`.
- **`--use` precedence (grilled, spec §4.5):** the build Manifest's `arch` overrides `settings.general.arch` for the run (QEMU binary, accel/topology per ADR-0001, gdb `set architecture`, rootfs arch); runtime/debugger prefs (`ext`, `memory`, `smp`, `-append` toggles) come from the active config.
- **When a task changes existing behavior, UPDATE that file's existing tests too** — the whole suite (`uv run pytest -q`) must stay green, not just new tests.
- Branching: `main` untouched; **`dev` stays local (not pushed)**; feature branch `feat/m1-cache-mgmt` off `dev`.
- Volume mode is the only supported runtime (`require_volume_mode`); the management commands operate on the `likedbg_ksrc` volume + `artifacts/cache/{builds,rootfs}/` host manifests. `--list` is Docker-free (reads host manifests); `--clean`/`--use` need the Docker client.
- **v1 scope note:** `--use` requires the rootfs to be *already cached* (the active-config rootfs label, or `--rootfs <label>`); it does not build a rootfs on the fly (that depends on the rootfs.sh builder, fixed separately). A missing rootfs → `CacheError` telling the user how to obtain one.

---

### Task 1: `cache.list_manifests`

Read every manifest of a kind from the registry.

**Files:**
- Modify: `src/likedbg/cache.py`
- Modify: `tests/test_cache_manifest.py`

**Interfaces:**
- Consumes: `manifest_path`, `load_manifest`, `_KIND_DIR`, `Manifest`.
- Produces: `cache.list_manifests(workspace: Path, kind: str) -> list[Manifest]` — loads all `<ws>/artifacts/cache/<dir>/*.json` for the kind, sorted by label; returns `[]` if the directory is absent.

- [ ] **Step 1: Write the failing test** — append to `tests/test_cache_manifest.py`:

```python
from likedbg.cache import list_manifests


def test_list_manifests_empty_when_no_dir(tmp_path):
    assert list_manifests(tmp_path, "build") == []


def test_list_manifests_returns_all_of_a_kind_sorted(tmp_path):
    for label in ("linux-6.6.30-bbbb", "linux-6.1.0-aaaa"):
        write_manifest(tmp_path, Manifest(kind="build", label=label, key="k", version="x",
                                          arch="arm64", storage_mode="volume"))
    write_manifest(tmp_path, Manifest(kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k",
                                      version="", arch="arm64", storage_mode="volume"))
    builds = list_manifests(tmp_path, "build")
    assert [m.label for m in builds] == ["linux-6.1.0-aaaa", "linux-6.6.30-bbbb"]
    assert [m.label for m in list_manifests(tmp_path, "rootfs")] == ["rootfs-arm64-bookworm-cccc"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_manifest.py -k list_manifests -v`
Expected: FAIL — `ImportError: cannot import name 'list_manifests'`.

- [ ] **Step 3: Add `list_manifests` to `src/likedbg/cache.py`** (after `load_manifest`):

```python
def list_manifests(workspace: Path, kind: str) -> list[Manifest]:
    registry = workspace / "artifacts" / "cache" / _KIND_DIR[kind]
    if not registry.is_dir():
        return []
    return [load_manifest(workspace, kind, p.stem) for p in sorted(registry.glob("*.json"))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_manifest.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_manifest.py
git commit -m "feat(cache): list_manifests reads all manifests of a kind"
```

---

### Task 2: `cache.remove_cached`

Delete a cached artifact's footprint + its manifest.

**Files:**
- Modify: `src/likedbg/cache.py`
- Create: `tests/test_cache_remove.py`

**Interfaces:**
- Consumes: `ContainerService` (`run_detached`/`exec`/`stop`), `Manifest`, `manifest_path`.
- Produces: `cache.remove_cached(container: ContainerService, workspace: Path, manifest: Manifest, *, volume: str = "likedbg_ksrc") -> None`.
  - build kind: `rm -rf /ksrc/<label>` in a `like_dbg_base` container (volume mounted rw), then `shutil.rmtree` the host export dir `<ws>/artifacts/<label>` (if present), then unlink the manifest.
  - rootfs kind: unlink the host image at `paths["image_host"]` (if a file), then unlink the manifest.
- Adds module constants `_BASE_IMAGE = "like_dbg_base"`, `_VOLUME_MOUNT = "/ksrc"` and imports `shutil` + `ContainerService`.

- [ ] **Step 1: Write the failing test** — create `tests/test_cache_remove.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.cache import Manifest, manifest_exists, remove_cached, write_manifest
from likedbg.container_service import ContainerService


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_remove_build_rms_volume_tree_and_host_export_and_manifest(tmp_path):
    label = "linux-6.6.30-aaaa"
    write_manifest(tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30",
                                      arch="arm64", storage_mode="volume"))
    export = tmp_path / "artifacts" / label
    export.mkdir(parents=True)
    (export / "Image").write_bytes(b"img")
    c = FakeC()
    remove_cached(c, tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30",
                                        arch="arm64", storage_mode="volume"))
    assert any(f"rm -rf /ksrc/{label}" in e for e in c.execs)
    assert not export.exists()
    assert manifest_exists(tmp_path, "build", label) is False


def test_remove_rootfs_unlinks_image_and_manifest(tmp_path):
    label = "rootfs-arm64-bookworm-cccc"
    img = tmp_path / "artifacts" / "rootfs" / f"{label}.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"img")
    write_manifest(tmp_path, Manifest(kind="rootfs", label=label, key="k", version="", arch="arm64",
                                      storage_mode="volume", paths={"image_host": str(img)}))
    c = FakeC()
    remove_cached(c, tmp_path, Manifest(kind="rootfs", label=label, key="k", version="", arch="arm64",
                                        storage_mode="volume", paths={"image_host": str(img)}))
    assert c.execs == []  # rootfs lives on the host; no container needed
    assert not img.exists()
    assert manifest_exists(tmp_path, "rootfs", label) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_remove.py -v`
Expected: FAIL — `ImportError: cannot import name 'remove_cached'`.

- [ ] **Step 3: Add `remove_cached` to `src/likedbg/cache.py`** (add `import shutil` to the top imports and `from likedbg.container_service import ContainerService`; add the constants near the other module constants):

```python
_BASE_IMAGE = "like_dbg_base"
_VOLUME_MOUNT = "/ksrc"


def remove_cached(container: ContainerService, workspace: Path, manifest: Manifest, *, volume: str = "likedbg_ksrc") -> None:
    if manifest.kind == "build":
        c = container.run_detached(_BASE_IMAGE, volumes={volume: {"bind": _VOLUME_MOUNT, "mode": "rw"}},
                                   detach=True, tty=True)
        try:
            container.exec(c, f"rm -rf {_VOLUME_MOUNT}/{manifest.label}")
        finally:
            container.stop(c)
        export_dir = workspace / "artifacts" / manifest.label
        if export_dir.is_dir():
            shutil.rmtree(export_dir)
    else:
        image = Path(manifest.paths.get("image_host", ""))
        if image.is_file():
            image.unlink()
    manifest_path(workspace, manifest.kind, manifest.label).unlink(missing_ok=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_remove.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_remove.py
git commit -m "feat(cache): remove_cached deletes artifact footprint + manifest"
```

---

### Task 3: `--list`

Docker-free listing of cached builds + rootfs images.

**Files:**
- Modify: `src/likedbg/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `cache.list_manifests`, `cache.manifest_path`, `Manifest`.
- Produces:
  - `cli.summarize_cache(workspace: Path) -> list[str]` — returns printable lines: a header plus one line per cached build then rootfs, each `"<kind>  <label>  <version>  <arch>  <size>  <created>"` where size is the host-stat-able artifact size (build → `<ws>/artifacts/<label>/Image` if present else `-`; rootfs → `paths["image_host"]` size) and created is the manifest file's mtime (ISO date). Empty cache → a single `"(cache empty)"` line.
  - `cli.cmd_list(workspace: Path) -> int` — prints each line via `logger.info`, returns 0.
  - `main` parses `--list`; when set, runs `cmd_list` and returns **before** the Docker client / TMUX guard (Docker-free).

- [ ] **Step 1: Write the failing test** — append to `tests/test_cli.py`:

```python
from likedbg.cache import Manifest, write_manifest
from likedbg.cli import summarize_cache


def test_summarize_cache_empty(tmp_path):
    assert summarize_cache(tmp_path) == ["(cache empty)"]


def test_summarize_cache_lists_build_and_rootfs(tmp_path):
    write_manifest(tmp_path, Manifest(kind="build", label="linux-6.6.30-aaaa", key="k",
                                      version="6.6.30", arch="arm64", storage_mode="volume"))
    rimg = tmp_path / "artifacts" / "rootfs" / "rootfs-arm64-bookworm-cccc.img"
    rimg.parent.mkdir(parents=True)
    rimg.write_bytes(b"x" * 2048)
    write_manifest(tmp_path, Manifest(kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k",
                                      version="", arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(rimg)}))
    lines = summarize_cache(tmp_path)
    joined = "\n".join(lines)
    assert "linux-6.6.30-aaaa" in joined and "6.6.30" in joined
    assert "rootfs-arm64-bookworm-cccc" in joined
    assert "build" in joined and "rootfs" in joined
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -k summarize_cache -v`
Expected: FAIL — `ImportError: cannot import name 'summarize_cache'`.

- [ ] **Step 3: Add `summarize_cache` + `cmd_list` to `src/likedbg/cli.py`** (add `from datetime import datetime, timezone` and `from likedbg.cache import Manifest` to the imports):

```python
def _artifact_size(workspace: Path, manifest: Manifest) -> str:
    if manifest.kind == "build":
        image = workspace / "artifacts" / manifest.label / "Image"
    else:
        image = Path(manifest.paths.get("image_host", ""))
    return str(image.stat().st_size) if image.is_file() else "-"


def summarize_cache(workspace: Path) -> list[str]:
    builds = cache.list_manifests(workspace, "build")
    rootfs = cache.list_manifests(workspace, "rootfs")
    if not builds and not rootfs:
        return ["(cache empty)"]
    lines = ["kind    label  version  arch  size  created"]
    for m in [*builds, *rootfs]:
        mp = cache.manifest_path(workspace, m.kind, m.label)
        created = datetime.fromtimestamp(mp.stat().st_mtime, tz=timezone.utc).date().isoformat()
        lines.append(f"{m.kind}  {m.label}  {m.version or '-'}  {m.arch}  {_artifact_size(workspace, m)}  {created}")
    return lines


def cmd_list(workspace: Path) -> int:
    for line in summarize_cache(workspace):
        logger.info(line)
    return 0
```

- [ ] **Step 4: Wire `--list` into `main`** — add `parser.add_argument("--list", action="store_true")`, and at the **start of the `try` block** (right after `workspace = Path.cwd()`):

```python
        if args.list:
            return cmd_list(workspace)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): --list cached builds + rootfs (Docker-free)"
```

---

### Task 4: `--clean` / `--clean-all`

Remove a selected cached artifact, or everything.

**Files:**
- Modify: `src/likedbg/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `cache.list_manifests`, `cache.load_manifest`, `cache.remove_cached`, `cache.manifest_exists`, `ContainerService`, `CacheError`.
- Produces:
  - `cli.cmd_clean(container: ContainerService, workspace: Path, *, label: str | None, clean_all: bool) -> int` — if `clean_all`, remove every build + rootfs manifest's artifact; else resolve `label` to a build or rootfs manifest (`CacheError` if neither exists, remedy "run `start_kgdb --list`") and remove it. Logs each removed label; returns 0.
  - `main` parses `--clean LABEL` and `--clean-all`; when either is set, runs `cmd_clean` after the Docker client/container are created and **before** the TMUX guard (needs Docker, not tmux).

- [ ] **Step 1: Write the failing test** — append to `tests/test_cli.py`:

```python
from likedbg.cli import cmd_clean
from likedbg.errors import CacheError


def test_cmd_clean_unknown_label_raises(tmp_path):
    with pytest.raises(CacheError):
        cmd_clean(_FakeContainer(), tmp_path, label="nope", clean_all=False)


def test_cmd_clean_all_removes_every_manifest(tmp_path):
    write_manifest(tmp_path, Manifest(kind="build", label="linux-6.6.30-aaaa", key="k",
                                      version="6.6.30", arch="arm64", storage_mode="volume"))
    write_manifest(tmp_path, Manifest(kind="rootfs", label="rootfs-arm64-bookworm-cccc", key="k",
                                      version="", arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(tmp_path / "gone.img")}))
    rc = cmd_clean(_FakeContainer(), tmp_path, label=None, clean_all=True)
    assert rc == 0
    assert cache.list_manifests(tmp_path, "build") == []
    assert cache.list_manifests(tmp_path, "rootfs") == []
```

Add this fake near the top of `tests/test_cli.py` if not already present:

```python
from types import SimpleNamespace

from likedbg.container_service import ContainerService


class _FakeContainer(ContainerService):
    def __init__(self):
        pass

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -k cmd_clean -v`
Expected: FAIL — `ImportError: cannot import name 'cmd_clean'`.

- [ ] **Step 3: Add `cmd_clean` to `src/likedbg/cli.py`**:

```python
def cmd_clean(container: ContainerService, workspace: Path, *, label: str | None, clean_all: bool) -> int:
    if clean_all:
        targets = [*cache.list_manifests(workspace, "build"), *cache.list_manifests(workspace, "rootfs")]
    else:
        kind = next((k for k in ("build", "rootfs") if cache.manifest_exists(workspace, k, label or "")), None)
        if kind is None:
            raise CacheError(f"no cached artifact labelled {label!r}", remedy="run `start_kgdb --list`")
        targets = [cache.load_manifest(workspace, kind, label or "")]
    for m in targets:
        cache.remove_cached(container, workspace, m)
        logger.info(f"removed {m.kind} {m.label}")
    return 0
```

Add `from likedbg.errors import CacheError` to the imports (alongside the existing error imports).

- [ ] **Step 4: Wire `--clean`/`--clean-all` into `main`** — add `parser.add_argument("--clean", default="")` and `parser.add_argument("--clean-all", action="store_true")`; after `container = ContainerService(client)` and before the `if args.adopt:` block:

```python
        if args.clean or args.clean_all:
            return cmd_clean(container, workspace, label=args.clean or None, clean_all=args.clean_all)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): --clean <label> / --clean-all"
```

---

### Task 5: `--use <label>` (boot a cached build directly)

**Files:**
- Modify: `src/likedbg/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `cache.load_manifest`, `cache.manifest_exists`, `make_rootfs_recipe`, `load_settings`, `HostProfile.detect`, `require_volume_mode`, `Session`, the stages, `gdb_pane_command`/`qemu_pane_command`.
- Produces:
  - `cli.build_use_pipeline(session, *, debugger_image, ext, panes, gdb_mount_source) -> Pipeline` — launch-only: `Pipeline([ArtifactExporter(container, …), DebuggeeStage(launch=…), DebuggerStage(ext=…, run_gdb=…, breakpoint="start_kernel")])`. (Export is idempotent; the kernel build + rootfs are already produced.) Takes `container`, `workspace`, `kernel_volume` like `build_pipeline`.
  - `cli.cmd_use(container, session, workspace, *, label, rootfs_label, panes) -> int` — load the build Manifest (`CacheError` if absent); re-load settings with `overrides={"general": {"arch": <manifest arch>}}`; detect host from those settings; `require_volume_mode`; resolve the rootfs image (from `--rootfs` label or the active rootfs label — `CacheError` if not cached); populate a `PipelineContext` (`build_label`, `kernel_root`, `vmlinux` = `paths["gdb_vmlinux"]`, `kernel_image` = `paths["image_in_tree"]`, `rootfs_image`, `rootfs_label`); run `build_use_pipeline` (using `paths["gdb_mount_source"]`); return 0.
  - `main` parses `--use LABEL` and `--rootfs LABEL`; when `--use` is set, runs the tmux path (TMUX guard, session, panes) then `cmd_use`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_cli.py`:

```python
from likedbg.cli import build_use_pipeline


def test_build_use_pipeline_is_launch_only(tmp_path):
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: None)
    pipe = build_use_pipeline(
        _FakeContainer(), session, workspace=tmp_path, kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest", ext="pwndbg", panes=(1, 2),
        gdb_mount_source="likedbg_ksrc",
    )
    assert [s.name for s in pipe._stages] == ["export", "debuggee", "debugger"]  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -k build_use_pipeline -v`
Expected: FAIL — `ImportError: cannot import name 'build_use_pipeline'`.

- [ ] **Step 3: Add `build_use_pipeline` + `cmd_use` to `src/likedbg/cli.py`**:

```python
def build_use_pipeline(
    container: ContainerService,
    session: Session,
    *,
    workspace: Path,
    kernel_volume: str,
    debugger_image: str,
    ext: str,
    panes: tuple[int, int],
    gdb_mount_source: str,
) -> Pipeline:
    debuggee_pane, debugger_pane = panes

    def launch_qemu(argv: list[str]) -> None:
        session.select_pane(debuggee_pane)
        session.send_keys(qemu_pane_command(argv))

    def run_gdb(args: list[str]) -> None:
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, mount_source=gdb_mount_source))

    return Pipeline(
        [
            ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
            DebuggeeStage(launch=launch_qemu),
            DebuggerStage(ext=ext, run_gdb=run_gdb, breakpoint="start_kernel"),
        ]
    )


def cmd_use(
    container: ContainerService,
    session: Session,
    workspace: Path,
    *,
    label: str,
    rootfs_label: str | None,
    panes: tuple[int, int],
) -> int:
    if not cache.manifest_exists(workspace, "build", label):
        raise CacheError(f"no cached build labelled {label!r}", remedy="run `start_kgdb --list`")
    bm = cache.load_manifest(workspace, "build", label)
    # Build identity (arch) is authoritative; reload settings with the arch override so the
    # host profile / QEMU follow the cached build, keeping runtime+debugger prefs from config.
    use_settings = load_settings(
        workspace / "configs" / "system.ini",
        workspace / "configs" / "user.ini",
        overrides={"general": {"arch": bm.arch}},
    )
    host = HostProfile.detect(use_settings, workspace)
    require_volume_mode(host)
    rlabel = rootfs_label or make_rootfs_recipe(use_settings).label
    if not cache.manifest_exists(workspace, "rootfs", rlabel):
        raise CacheError(
            f"no cached rootfs labelled {rlabel!r}",
            remedy="run `start_kgdb` once to build a rootfs, or pass --rootfs <label> (see `--list`)",
        )
    rm = cache.load_manifest(workspace, "rootfs", rlabel)
    rootfs_image = Path(rm.paths["image_host"])
    if not rootfs_image.is_file():
        raise CacheError(f"cached rootfs {rlabel} image is gone", remedy=f"`start_kgdb --clean {rlabel}` and rebuild")
    ctx = PipelineContext(
        settings=use_settings,
        host=host,
        kernel_root=Path(bm.paths["kernel_root"]),
        vmlinux=Path(bm.paths["gdb_vmlinux"]),
        kernel_image=Path(bm.paths["image_in_tree"]),
        rootfs_image=rootfs_image,
        build_label=label,
        rootfs_label=rlabel,
    )
    pipeline = build_use_pipeline(
        container, session, workspace=workspace, kernel_volume="likedbg_ksrc",
        debugger_image="like_debugger:latest", ext=use_settings.debugger.ext, panes=panes,
        gdb_mount_source=bm.paths["gdb_mount_source"],
    )
    pipeline.run(ctx)
    return 0
```

- [ ] **Step 4: Wire `--use`/`--rootfs` into `main`** — add `parser.add_argument("--use", default="")` and `parser.add_argument("--rootfs", default="")`. Replace the default-run tail of `main` (from the TMUX guard onward) so `--use` shares the tmux setup but takes the launch-only path:

```python
        if not os.getenv("TMUX"):
            logger.error("Not running inside a TMUX session. Start tmux first.")
            return 2
        session = Session("LIKE-DBG")
        session.start("LIKE-DBG")
        panes = session.open_debug_layout()
        if args.use:
            return cmd_use(container, session, workspace,
                           label=args.use, rootfs_label=args.rootfs or None, panes=panes)
        host = HostProfile.detect(settings, workspace)
        require_volume_mode(host)
        ctx = PipelineContext(settings=settings, host=host, build_label=br.label, rootfs_label=rr.label)
        pipeline = build_pipeline(
            container, session, workspace=workspace, kernel_volume="likedbg_ksrc",
            dl_dir=workspace / "kernels", debugger_image="like_debugger:latest",
            ext=settings.debugger.ext, panes=panes, build_recipe=br, rootfs_recipe=rr,
        )
        pipeline.run(ctx)
        return 0
```

(`cmd_use` calls `HostProfile.detect` + `require_volume_mode` itself on the arch-overridden settings, so the default branch keeps its own detect.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v && uv run pytest -q && uv run mypy src/likedbg && uv run ruff check .`
Expected: all pass; mypy + ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): --use <label> boots a cached build directly (launch-only)"
```

---

### Task 6: Live verification (EMPIRICAL — controller-driven)

> Validate the three commands live against the existing cache (the adopted `linux-6.6.30-35e79946` build + the seeded `rootfs-arm64-bookworm-1c5f217c`).

- [ ] **Step 1:** Full gate green: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg`.
- [ ] **Step 2:** `uv run ./start_kgdb --list` (no tmux) → shows the cached build + rootfs rows (label/version/arch/size/created). Record output.
- [ ] **Step 3:** Inside tmux, `uv run ./start_kgdb --use linux-6.6.30-35e79946` → cache-hit (no build), native HVF boot in pane 1, debugger attached at `start_kernel` in pane 2. (Optionally `-c` a pwndbg config to confirm ext still selects.)
- [ ] **Step 4:** `uv run ./start_kgdb --clean <some-throwaway-label>` round-trip: create a dummy build manifest, `--list` shows it, `--clean` removes it, `--list` no longer shows it. (Do **not** clean the adopted build/rootfs the live gate depends on.)
- [ ] **Step 5:** Record results in `docs/superpowers/notes/2026-06-23-cache-management-live.md`; fold back any wiring fixes (keeping unit tests green); commit.

---

## Self-Review

- **Spec coverage (§4.5):** `--list` (Task 3) ✓; `--clean`/`--clean-all` (Task 4) ✓; `--use` with arch-authoritative precedence + rootfs resolution + launch-only pipeline (Task 5) ✓; supporting `list_manifests` (Task 1) + `remove_cached` (Task 2) ✓; live validation (Task 6) ✓. `--use` rootfs build-if-absent is a documented v1 deferral (depends on the rootfs.sh fix). This plan also makes the Plan-5 `CacheError` remedies that reference `--list`/`--clean` valid (those flags now exist).
- **Placeholder scan:** Tasks 1–5 carry complete code/tests; Task 6 is explicitly empirical.
- **Type consistency:** `list_manifests(workspace, kind) -> list[Manifest]`, `remove_cached(container, workspace, manifest, *, volume)`, `summarize_cache(workspace) -> list[str]`, `cmd_list(workspace) -> int`, `cmd_clean(container, workspace, *, label, clean_all) -> int`, `build_use_pipeline(container, session, *, workspace, kernel_volume, debugger_image, ext, panes, gdb_mount_source) -> Pipeline`, `cmd_use(container, session, workspace, settings, *, label, rootfs_label, panes) -> int` — consistent across tasks and tests. Manifest `paths` keys used (`kernel_root`, `gdb_vmlinux`, `image_in_tree`, `gdb_mount_source`, `image_host`) match those written by Plan 5's Build/Rootfs/adopt.
