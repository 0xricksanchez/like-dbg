# Section A — Foundation Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear all seven deferred Plan 5/6 polish items (shared constants, container auto-removal, a storage-mode guard, an adopt parse error, and three cache cosmetics) in one branch, behavior-preserving except for container auto-removal.

**Architecture:** Extract duplicated infra literals into a new `src/likedbg/constants.py` and migrate six callers to it; default `auto_remove=True` in `ContainerService.run_detached`; scope a storage-mode guard to `remove_cached`'s build branch; make `_parse_makefile_version` raise on missing fields; tidy three `cache.py` helpers. Each change is small, independent, and TDD-driven.

**Tech Stack:** Python 3.12, docker-py, Pydantic (config), pytest, mypy `--strict`, ruff (lint + format), `uv` runner.

## Global Constraints

- Run everything via `uv run` (e.g. `uv run pytest`, `uv run mypy src/likedbg`, `uv run ruff check`).
- NOTE: type-check with `uv run mypy src/likedbg` (the project's mypy `files` scope). Do NOT run `uv run mypy src/likedbg` — it overrides the config scope and trips over the quarantined legacy `src/debuggee.py` ("found twice under different module names"), which is unrelated to this work.
- Tests live in `./tests/`; package lives in `src/likedbg/`. Quarantined legacy `src/*.py` is ruff-excluded — **do not touch it**.
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit.
- `mypy --strict`, `ruff check`, and `ruff format --check` must all be green before each commit.
- The full suite (128 tests at baseline) must stay green after every task.
- Branch is `chore/section-a-hardening` off `dev`; commit locally, **never `git push`** (`dev` stays local).
- The working tree has unrelated in-flight user edits (`.dockerfile_*`, `configs/user.ini`, `ctf/misc/cpio.sh`, `CODE_OF_CONDUCT.md`) — **never `git add` those**; stage only the exact files each step names.
- Extraction is behavior-preserving: constants equal the existing literals verbatim, except `BASE_IMAGE` is normalized to `like_dbg_base:latest` (Docker already implies `:latest`).

---

### Task 1: Create the shared constants module

**Files:**
- Create: `src/likedbg/constants.py`
- Test: `tests/test_constants.py`

**Interfaces:**
- Consumes: nothing (imports no internal module → no import cycles).
- Produces: module `likedbg.constants` exporting `KERNEL_VOLUME: str`, `VOLUME_MOUNT: str`, `BASE_IMAGE: str`, `KBUILDER_IMAGE: str`, `ROOTFS_IMAGE: str`, `DEBUGGER_IMAGE: str`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_constants.py`:

```python
from likedbg import constants


def test_volume_and_mount_values():
    assert constants.KERNEL_VOLUME == "likedbg_ksrc"
    assert constants.VOLUME_MOUNT == "/ksrc"


def test_image_tags_are_tagged_latest():
    # All image identifiers carry an explicit :latest tag for one consistent convention.
    for tag in (
        constants.BASE_IMAGE,
        constants.KBUILDER_IMAGE,
        constants.ROOTFS_IMAGE,
        constants.DEBUGGER_IMAGE,
    ):
        assert tag.endswith(":latest")


def test_base_image_is_like_dbg_base():
    assert constants.BASE_IMAGE == "like_dbg_base:latest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_constants.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.constants'` (or import error).

- [ ] **Step 3: Write the module**

Create `src/likedbg/constants.py`:

```python
"""Shared infrastructure literals: image tags, the kernel-source volume, and its mount.

These name the project's Docker images and the named volume that holds kernel source in
Volume mode (see CONTEXT.md -> Storage mode, ADR-0002). They are infra identifiers, not
user configuration, so they live here rather than in the Pydantic Settings schema.
"""

from __future__ import annotations

KERNEL_VOLUME = "likedbg_ksrc"
VOLUME_MOUNT = "/ksrc"

BASE_IMAGE = "like_dbg_base:latest"
# NOTE: the kbuilder image is clang-universal (cross-compiles any arch); the `_arm64`
# suffix is a legacy misnomer. Revisit the name when x86_64-on-Mac lands (ROADMAP section B).
KBUILDER_IMAGE = "like_kbuilder_arm64:latest"
ROOTFS_IMAGE = "like_rootfs:latest"
DEBUGGER_IMAGE = "like_debugger:latest"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_constants.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Lint + type-check**

Run: `uv run ruff check src/likedbg/constants.py tests/test_constants.py && uv run ruff format src/likedbg/constants.py tests/test_constants.py && uv run mypy src/likedbg`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/constants.py tests/test_constants.py
git commit -m "feat(constants): shared infra literals module (images, volume, mount)"
```

---

### Task 2: Migrate all callers to `constants`

**Files:**
- Modify: `src/likedbg/cli.py`, `src/likedbg/cache.py`, `src/likedbg/adopt.py`, `src/likedbg/stages/export.py`, `src/likedbg/stages/build.py`, `src/likedbg/stages/unpack.py`

**Interfaces:**
- Consumes: `likedbg.constants` (Task 1).
- Produces: no signature changes; `cache.locations` / `cache.remove_cached` / `adopt.adopt_legacy_build` keep `volume: str = KERNEL_VOLUME` defaults (same value as before). This is a pure substitution — later tasks are unaffected.

This task has no new test; its proof is the **existing suite staying green**. Each edit replaces a literal (or a per-module `_BASE_IMAGE`/`_VOLUME_MOUNT`) with the shared constant. Keep `_MOUNT = "/io"` (build/unpack) and `_OUT_MOUNT = "/out"` (export) as-is — they are out of scope per the spec.

- [ ] **Step 1: Edit `src/likedbg/cli.py`**

Add this import (alphabetical, after the other `likedbg.` imports near the top):

```python
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import ROOTFS_IMAGE
```

Replace these literals (all occurrences):
- `kbuilder_image="like_kbuilder_arm64:latest",` -> `kbuilder_image=KBUILDER_IMAGE,`
- `rootfs_image="like_rootfs:latest",` -> `rootfs_image=ROOTFS_IMAGE,`
- `kernel_volume="likedbg_ksrc",` (×2) -> `kernel_volume=KERNEL_VOLUME,`
- `debugger_image="like_debugger:latest",` (×2) -> `debugger_image=DEBUGGER_IMAGE,`

- [ ] **Step 2: Edit `src/likedbg/cache.py`**

Delete the module-private constants:

```python
_BASE_IMAGE = "like_dbg_base"
_VOLUME_MOUNT = "/ksrc"
```

Add imports (after `from likedbg.config import Settings`):

```python
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
```

Apply these replacements:
- `def locations(label: str, *, arch: str, storage_mode: str, workspace: Path, volume: str = "likedbg_ksrc")` -> `... volume: str = KERNEL_VOLUME)`
- `container_root = f"/ksrc/{label}"` -> `container_root = f"{VOLUME_MOUNT}/{label}"`
- `gdb_vmlinux="/ksrc/vmlinux",` (in the bind-mode branch) -> `gdb_vmlinux=f"{VOLUME_MOUNT}/vmlinux",`
- in `remove_cached(...)` signature: `volume: str = "likedbg_ksrc"` -> `volume: str = KERNEL_VOLUME`
- `container.run_detached(\n            _BASE_IMAGE, ...` -> `BASE_IMAGE`
- `container.exec(c, f"rm -rf {_VOLUME_MOUNT}/{manifest.label}")` -> `f"rm -rf {VOLUME_MOUNT}/{manifest.label}"`

(Leave the `# bind mode mounts ...` comment lines unchanged.)

- [ ] **Step 3: Edit `src/likedbg/adopt.py`**

Delete:

```python
_BASE_IMAGE = "like_dbg_base"
_VOLUME_MOUNT = "/ksrc"
```

Add imports (after `from likedbg.errors import CacheError`):

```python
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
```

Apply:
- `def adopt_legacy_build(container: Any, *, workspace: Path, recipe: BuildRecipe, volume: str = "likedbg_ksrc")` -> `... volume: str = KERNEL_VOLUME)`
- `legacy = f"/ksrc/linux-{recipe.version}"` -> `legacy = f"{VOLUME_MOUNT}/linux-{recipe.version}"`
- `c = container.run_detached(\n        _BASE_IMAGE, ...` -> `BASE_IMAGE`
- `container.exec(c, f"mv {legacy} /ksrc/{label}")` -> `f"mv {legacy} {VOLUME_MOUNT}/{label}"`

- [ ] **Step 4: Edit `src/likedbg/stages/export.py`** (this is item #4)

Delete:

```python
_VOLUME_MOUNT = "/ksrc"
_BASE_IMAGE = "like_dbg_base"
```

(Keep `_OUT_MOUNT = "/out"`.) Add imports (after `from likedbg.pipeline import PipelineContext`):

```python
from likedbg.constants import BASE_IMAGE
from likedbg.constants import VOLUME_MOUNT
```

Apply:
- `vmlinux_in_tree = f"/ksrc/{label}/vmlinux"` -> `vmlinux_in_tree = f"{VOLUME_MOUNT}/{label}/vmlinux"`
- `self._volume: {"bind": _VOLUME_MOUNT, "mode": "ro"},` -> `{"bind": VOLUME_MOUNT, "mode": "ro"},`
- `container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)` -> `run_detached(BASE_IMAGE, ...)`

- [ ] **Step 5: Edit `src/likedbg/stages/build.py`**

Delete `_VOLUME_MOUNT = "/ksrc"` (keep `_MOUNT = "/io"`). Add import (after `from likedbg.errors import BuildError`):

```python
from likedbg.constants import VOLUME_MOUNT
```

Apply:
- `self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},` -> `{"bind": VOLUME_MOUNT, "mode": "rw"},`

(build.py uses the injected `self._image` for the kbuilder image — no constant needed there.)

- [ ] **Step 6: Edit `src/likedbg/stages/unpack.py`**

Delete:

```python
_VOLUME_MOUNT = "/ksrc"
_BASE_IMAGE = "like_dbg_base"
```

(Keep `_MOUNT = "/io"`.) Add imports (after `from likedbg.errors import UnpackError`):

```python
from likedbg.constants import BASE_IMAGE
from likedbg.constants import VOLUME_MOUNT
```

Apply:
- `ctx.kernel_root = Path(f"/ksrc/{label}")` -> `Path(f"{VOLUME_MOUNT}/{label}")`
- `keyed = f"/ksrc/{label}"` -> `keyed = f"{VOLUME_MOUNT}/{label}"`
- `self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},` -> `{"bind": VOLUME_MOUNT, "mode": "rw"},`
- `container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)` -> `run_detached(BASE_IMAGE, ...)`

- [ ] **Step 7: Run the full suite + lint + types**

Run: `uv run ruff format src tests && uv run ruff check src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: ruff/mypy clean; pytest 128+ passed (the existing suite is unchanged — `test_cache_locations.py` still sees `gdb_mount_source == "likedbg_ksrc"` because `KERNEL_VOLUME == "likedbg_ksrc"`).

- [ ] **Step 8: Commit**

```bash
git add src/likedbg/cli.py src/likedbg/cache.py src/likedbg/adopt.py src/likedbg/stages/export.py src/likedbg/stages/build.py src/likedbg/stages/unpack.py
git commit -m "refactor: route image/volume literals through constants module"
```

---

### Task 3: `run_detached` defaults to `auto_remove=True`

**Files:**
- Modify: `src/likedbg/container_service.py:42-43`
- Test: `tests/test_container_service.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ContainerService.run_detached(self, image: str, *, auto_remove: bool = True, **kwargs: Any) -> Any` — every existing caller (no caller passes `auto_remove`) now gets `auto_remove=True` forwarded to `containers.run`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_container_service.py`:

```python
def test_run_detached_defaults_to_auto_remove():
    client = FakeClient()
    svc = ContainerService(client)
    svc.run_detached("img", detach=True, tty=True)
    assert client.containers.run_kwargs["auto_remove"] is True


def test_run_detached_auto_remove_can_be_overridden():
    client = FakeClient()
    svc = ContainerService(client)
    svc.run_detached("img", auto_remove=False, detach=True, tty=True)
    assert client.containers.run_kwargs["auto_remove"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_container_service.py -k auto_remove -v`
Expected: FAIL — `KeyError: 'auto_remove'` (the kwarg is not forwarded yet).

- [ ] **Step 3: Implement**

In `src/likedbg/container_service.py`, replace the `run_detached` method:

```python
    def run_detached(self, image: str, *, auto_remove: bool = True, **kwargs: Any) -> Any:
        """Run a short-lived utility container detached and return its handle.

        Intended for ephemeral helpers that do work then stop (unpack/build/rootfs/export/
        adopt/cache-removal). ``auto_remove=True`` (default) lets the daemon delete the
        container once it stops, so stopped containers do not accumulate. Long-lived guests
        (the Debuggee and Debugger) are launched as tmux ``docker run`` pane commands, NOT
        through this method.
        """
        return self._client.containers.run(image, auto_remove=auto_remove, **kwargs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_container_service.py -v`
Expected: PASS (all, including the two new ones and the existing `test_run_detached_passes_through`).

- [ ] **Step 5: Lint + type-check + full suite**

Run: `uv run ruff check src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; full suite green (the stage tests use their own `run_detached` fakes, so they are unaffected).

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/container_service.py tests/test_container_service.py
git commit -m "fix(container): run_detached auto-removes utility containers by default"
```

---

### Task 4: `remove_cached` guards the build branch on storage mode

**Files:**
- Modify: `src/likedbg/cache.py` (the `remove_cached` function, `if manifest.kind == "build":` branch)
- Test: `tests/test_cache_remove.py`

**Interfaces:**
- Consumes: `CacheError` (already imported in `cache.py`).
- Produces: `remove_cached` raises `CacheError` for a `kind="build"` manifest whose `storage_mode != "volume"`, before touching the volume. The rootfs branch is unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cache_remove.py` (add `import pytest` and `from likedbg.errors import CacheError` at the top if absent):

```python
def test_remove_build_refuses_non_volume_storage(tmp_path):
    label = "linux-6.6.30-bbbb"
    m = Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="bind")
    write_manifest(tmp_path, m)
    with pytest.raises(CacheError):
        remove_cached(FakeC(), tmp_path, m)
    # the manifest is preserved (nothing was removed)
    assert manifest_exists(tmp_path, "build", label) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_remove.py::test_remove_build_refuses_non_volume_storage -v`
Expected: FAIL — no exception is raised (the function assumes volume and tries to run a container / unlink the manifest).

- [ ] **Step 3: Implement**

In `cache.py`'s `remove_cached`, add the guard as the first statement inside the build branch:

```python
    if manifest.kind == "build":
        if manifest.storage_mode != "volume":
            raise CacheError(
                f"cache removal for {manifest.storage_mode!r}-mode builds is not yet wired",
                remedy="this milestone targets Volume mode; Bind/Linux runtime is gated (see require_volume_mode)",
            )
        c = container.run_detached(
            BASE_IMAGE, volumes={volume: {"bind": VOLUME_MOUNT, "mode": "rw"}}, detach=True, tty=True
        )
        ...
```

(Leave the rest of the branch and the `else` rootfs branch unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_remove.py -v`
Expected: PASS — the new guard test plus the existing volume-build and rootfs removal tests.

- [ ] **Step 5: Lint + type-check**

Run: `uv run ruff check src tests && uv run mypy src/likedbg`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_remove.py
git commit -m "fix(cache): remove_cached refuses non-volume builds with a clear error"
```

---

### Task 5: `_parse_makefile_version` raises on missing fields

**Files:**
- Modify: `src/likedbg/adopt.py:17-23`
- Test: `tests/test_adopt.py`

**Interfaces:**
- Consumes: `CacheError` (already imported in `adopt.py`).
- Produces: `_parse_makefile_version(text: str) -> str` raises `CacheError` when any of VERSION/PATCHLEVEL/SUBLEVEL is missing; returns the dotted version otherwise.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_adopt.py`:

```python
def test_parse_makefile_version_parses_valid():
    from likedbg.adopt import _parse_makefile_version

    assert _parse_makefile_version("VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\n") == "6.6.30"


def test_parse_makefile_version_raises_on_missing_field():
    from likedbg.adopt import _parse_makefile_version

    with pytest.raises(CacheError):
        _parse_makefile_version("VERSION = 6\nPATCHLEVEL = 6\n")  # SUBLEVEL missing
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_adopt.py -k parse_makefile_version -v`
Expected: the `raises` test FAILS — the current code returns `"6.6.None"` instead of raising. (`test_parse_makefile_version_parses_valid` already passes.)

- [ ] **Step 3: Implement**

Replace `_parse_makefile_version` in `adopt.py`:

```python
def _parse_makefile_version(text: str) -> str:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
            if line.startswith(key) and "=" in line:
                fields[key] = line.split("=", 1)[1].strip()
    missing = [k for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL") if not fields.get(k)]
    if missing:
        raise CacheError(
            f"could not parse kernel version from Makefile (missing {', '.join(missing)})",
            remedy="point at a real kernel tree, or build fresh",
        )
    return f"{fields['VERSION']}.{fields['PATCHLEVEL']}.{fields['SUBLEVEL']}"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_adopt.py -v`
Expected: PASS — both new tests plus the three existing adopt tests (the success/mismatch paths still parse valid Makefiles).

- [ ] **Step 5: Lint + type-check**

Run: `uv run ruff check src tests && uv run mypy src/likedbg`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/adopt.py tests/test_adopt.py
git commit -m "fix(adopt): clear error when the legacy Makefile version cannot be parsed"
```

---

### Task 6: `cache.py` cosmetics — `slug` docstring/test, `list_manifests` sort, `write_manifest` unique temp

**Files:**
- Modify: `src/likedbg/cache.py` (imports, `slug`, `list_manifests`, `write_manifest`)
- Test: `tests/test_cache_primitives.py` (for `slug`), `tests/test_cache_manifest.py` (for `write_manifest`)

**Interfaces:**
- Consumes: nothing new.
- Produces: behavior unchanged for callers; `slug` gains a docstring, `list_manifests` sorts by `p.stem`, `write_manifest` writes via a unique temp file.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cache_primitives.py`:

```python
def test_slug_empty_string():
    from likedbg.cache import slug

    assert slug("") == ""


def test_slug_already_clean_roundtrips():
    from likedbg.cache import slug

    assert slug("linux-6.6.30") == "linux-6.6.30"
```

Add to `tests/test_cache_manifest.py` (it already imports `Manifest` and `write_manifest`; reuse those imports):

```python
def test_write_manifest_leaves_no_tmp_residue(tmp_path):
    from likedbg.cache import write_manifest, Manifest

    write_manifest(
        tmp_path,
        Manifest(kind="build", label="linux-6.6.30-zzzz", key="k", version="6.6.30", arch="arm64", storage_mode="volume"),
    )
    builds = tmp_path / "artifacts" / "cache" / "builds"
    assert list(builds.glob("*.tmp")) == []
```

- [ ] **Step 2: Run tests to verify the new ones fail / pass appropriately**

Run: `uv run pytest tests/test_cache_primitives.py tests/test_cache_manifest.py -v`
Expected: `test_slug_empty_string` and `test_slug_already_clean_roundtrips` already PASS (current `slug` already behaves this way — they lock the contract before the docstring edit). `test_write_manifest_leaves_no_tmp_residue` already PASSES too (current code uses `tmp.replace`, so no residue) — it guards the refactor. This task is refactor-under-test: the tests pin behavior, then we change the implementation without breaking them.

- [ ] **Step 3: Add `os` and `tempfile` imports to `cache.py`**

At the top of `src/likedbg/cache.py`, alongside the existing `import hashlib` / `import json` block, add:

```python
import os
import tempfile
```

(Keep imports alphabetically grouped; ruff format will enforce order.)

- [ ] **Step 4: Add the `slug` docstring**

Replace the `slug` function:

```python
def slug(text: str) -> str:
    """Kebab-slug for Labels: lowercase, collapse runs of non-[a-z0-9._-] to '-', trim '-'."""
    return _SLUG_RE.sub("-", text.lower()).strip("-")
```

- [ ] **Step 5: Make `list_manifests` sort explicit**

Replace the return line of `list_manifests`:

```python
    return [load_manifest(workspace, kind, p.stem) for p in sorted(registry.glob("*.json"), key=lambda p: p.stem)]
```

- [ ] **Step 6: Make `write_manifest` use a unique temp file**

Replace the `write_manifest` function body:

```python
def write_manifest(workspace: Path, manifest: Manifest) -> Path:
    path = manifest_path(workspace, manifest.kind, manifest.label)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, suffix=".json.tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(manifest.__dict__, indent=2, sort_keys=True))
        tmp.replace(path)  # atomic on the same filesystem
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path
```

- [ ] **Step 7: Run tests + lint + types + full suite**

Run: `uv run ruff format src tests && uv run ruff check src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; full suite green (`load_manifest` round-trips the freshly written manifest; `list_manifests` ordering tests unchanged).

- [ ] **Step 8: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_primitives.py tests/test_cache_manifest.py
git commit -m "refactor(cache): slug docstring, explicit list_manifests sort, unique manifest temp"
```

---

## Final verification (whole branch)

- [ ] **Full gate:** `uv run ruff format --check src tests && uv run ruff check src tests && uv run mypy src/likedbg && uv run pytest -q` — all green.
- [ ] **Spec coverage:** items #1 (Task 4), #2 (Tasks 1-2), #3 (Task 5), #4 (Task 2 / export.py), #5 (Task 6 slug + list_manifests), #6 (Task 6 write_manifest), #7 (Task 3) — all implemented.
- [ ] **Live gate (on the M5, volume mode), per spec §5:** run `uv run ./start_kgdb`; confirm (1) `docker ps -a` shows no leftover `like_dbg_base` / `like_kbuilder_arm64` / `like_rootfs` helper containers after the run, and (2) a deliberately-broken build still surfaces full output via `ContainerError`.
- [ ] **Finish:** use `superpowers:finishing-a-development-branch` to merge `chore/section-a-hardening` into `dev` **locally** (no push); then update the ROADMAP §A (mark items cleared) and the project memory.

## Self-Review

- **Spec coverage:** every spec section maps to a task (table above). The glossary term (`Storage mode`) was added during the grill and is already committed.
- **Placeholder scan:** no TBD/TODO; every code step shows complete code and exact commands.
- **Type consistency:** `run_detached(image, *, auto_remove=True, **kwargs)` is referenced consistently; `BASE_IMAGE`/`VOLUME_MOUNT`/`KERNEL_VOLUME` names match Task 1's definitions across Tasks 2 and 4; `_parse_makefile_version` signature unchanged (`str -> str`, now raising).
