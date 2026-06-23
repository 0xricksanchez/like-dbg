# M1 Plan 5 — Build Cache Engine + Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `start_kgdb` reuse a previously produced Kernel Build (and rootfs image) instead of rebuilding — keyed by an automatic content-hash of the requested config — and migrate the existing unkeyed build into the cache so the live boot+attach gate runs with zero rebuild.

**Architecture:** A dedicated `likedbg/cache.py` owns Recipe value objects (the single source of truth that makes the hashed inputs == the built inputs by construction), key/label derivation, the host-side Manifest registry, and storage-mode-aware location resolution. The Unpack/Build/Rootfs/Export stages become cache-aware: they consult the Manifest (present ⇒ reuse, populate context, skip work) and otherwise produce + write the Manifest. The CLI derives the recipes/labels and threads them through the pipeline; `--adopt` imports the legacy unkeyed tree; the live run is the empirical gate.

**Tech Stack:** Python 3.12, Pydantic, docker-py, hashlib/json, tmux, `qemu-system-aarch64 -accel hvf`, `gdb-multiarch`+GEF; uv/ruff/mypy.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-23-build-reuse-cache-design.md`. **Glossary:** `CONTEXT.md` (Kernel Build, Label, Manifest, Build Cache). **ADRs:** 0001 (topology), 0002 (bind vs volume), 0003 (config-not-toolchain identity).
- **Identity = requested config only** (ADR-0003): the cache key never includes toolchain/image identity. When patches/`custom_modules`/rootfs packages are wired into a stage later, their inputs MUST be added to that recipe's `cache_inputs` in the same change.
- **No-drift is a type invariant:** `BuildStage`/`RootfsStage` build *only from the Recipe*, never re-reading `settings` for build-affecting values.
- Package boundary: new code under `src/likedbg/`; tests under `tests/`; legacy flat `src/*.py` untouched (ruff `force-exclude`). `mypy --strict` clean over `src/likedbg`; `ruff check .` / `ruff format --check .` clean; line length 120. Run tools with `uv run`.
- Errors use `LikeDbgError` subclasses with `remedy=`; side-effects behind injected seams (`ContainerService`).
- Branching: `main` untouched. Work on `feat/m1-cache` off the current `feat/m1-live-cli` (which holds Plan 4 + fold-back fixes). Live validation may use `feat/m1-cache` directly.
- Manifests live under `<workspace>/artifacts/cache/{builds,rootfs}/<label>.json` (`artifacts/` is git-ignored). `created_at`/`size_bytes` are stamped by the CLI after a stage returns; stages record paths only.
- Storage mode (`ctx.host.storage_mode`): `"volume"` (macOS default) or `"bind"` (Linux; macOS case-sensitive). `locations()` is implemented and unit-tested for **both**; the empirical gate runs in **volume** mode.

---

### Task 1: CacheError + cache primitives

Pure foundations: the error type and the hash/slug helpers everything else builds on.

**Files:**
- Modify: `src/likedbg/errors.py`
- Create: `src/likedbg/cache.py`
- Create: `tests/test_cache_primitives.py`

**Interfaces:**
- Produces:
  - `errors.CacheError(LikeDbgError)`
  - `cache.cache_key(inputs: dict[str, str]) -> str` — sha256 of canonical JSON, full hex.
  - `cache.short_hash(key: str) -> str` — first 8 chars.
  - `cache.slug(text: str) -> str` — lowercased, filesystem-safe (`[a-z0-9._-]`, runs collapsed to `-`, stripped).

- [ ] **Step 1: Write the failing test** — create `tests/test_cache_primitives.py`:

```python
from likedbg.cache import cache_key, short_hash, slug


def test_cache_key_is_deterministic_and_order_independent():
    a = cache_key({"version": "6.6.30", "arch": "arm64"})
    b = cache_key({"arch": "arm64", "version": "6.6.30"})
    assert a == b
    assert len(a) == 64


def test_cache_key_is_sensitive_to_any_input_change():
    base = cache_key({"version": "6.6.30", "arch": "arm64"})
    assert cache_key({"version": "6.6.31", "arch": "arm64"}) != base
    assert cache_key({"version": "6.6.30", "arch": "x86_64"}) != base


def test_short_hash_is_first_eight():
    key = cache_key({"x": "y"})
    assert short_hash(key) == key[:8]


def test_slug_is_filesystem_safe():
    assert slug("6.6.30") == "6.6.30"
    assert slug("My Tag/v2") == "my-tag-v2"
    assert slug("--weird__") == "weird__"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_primitives.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.cache'`.

- [ ] **Step 3: Add `CacheError` to `src/likedbg/errors.py`** (after `ContainerError`):

```python
class CacheError(LikeDbgError):
    """Failure resolving, reusing, or migrating a cached Kernel Build / rootfs."""
```

- [ ] **Step 4: Create `src/likedbg/cache.py`**:

```python
"""Content-addressed Build Cache: Recipe value objects (single source of truth for what a
Kernel Build / rootfs is), key + Label derivation, the host-side Manifest registry, and
storage-mode-aware location resolution.

See docs/superpowers/specs/2026-06-23-build-reuse-cache-design.md and ADR-0003: a Kernel
Build is identified by its requested configuration, not by toolchain/image identity.
"""

from __future__ import annotations

import hashlib
import json
import re

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def cache_key(inputs: dict[str, str]) -> str:
    blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def short_hash(key: str) -> str:
    return key[:8]


def slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_primitives.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/errors.py src/likedbg/cache.py tests/test_cache_primitives.py
git commit -m "feat(cache): CacheError + cache_key/short_hash/slug primitives"
```

---

### Task 2: Recipes + builders + Labels

The Recipe value objects and the functions that derive them from settings. The Recipe is the no-drift seam: `cache_inputs()` is hashed, and the same object yields the concrete build params.

**Files:**
- Modify: `src/likedbg/cache.py`
- Create: `tests/test_cache_recipes.py`

**Interfaces:**
- Consumes: `toolchain.resolve_toolchain(compiler, arch) -> ToolchainEnv(make_vars, apt_packages)`; `config.Settings`; `stages.download.resolve_version(cfg) -> str`.
- Produces:
  - `cache.BuildRecipe` (frozen) with fields `version: str`, `arch: str`, `compiler: str`, `make_vars: tuple[tuple[str, str], ...]`, `frag_hashes: tuple[tuple[str, str], ...]`, `fragments: tuple[str, ...]`, `kernel_tag: str`; methods `env() -> dict[str, str]`, `cache_inputs() -> dict[str, str]`; properties `key -> str`, `label -> str`.
  - `cache.RootfsRecipe` (frozen) with `arch: str`, `distribution: str`, `hostname: str`; `cache_inputs()`; `key`; `label`.
  - `cache.build_recipe(settings, *, version, workspace, fragments) -> BuildRecipe`.
  - `cache.rootfs_recipe(settings) -> RootfsRecipe`.

- [ ] **Step 1: Write the failing test** — create `tests/test_cache_recipes.py`:

```python
from pathlib import Path

from likedbg.cache import BuildRecipe, RootfsRecipe, build_recipe, rootfs_recipe
from likedbg.config import Settings


def _frag(tmp_path: Path, name: str, body: str) -> str:
    rel = f"configs/fragments/{name}"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return rel


def test_build_recipe_label_and_inputs(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "kernel_builder": {"compiler": "clang"}})
    frags = [_frag(tmp_path, "debug.config", "CONFIG_DEBUG_INFO=y\n")]
    r = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=frags)
    assert r.arch == "arm64" and r.compiler == "clang"
    assert r.env() == {"ARCH": "arm64", "LLVM": "1"}
    assert r.cache_inputs()["version"] == "6.6.30"
    assert any(k.startswith("frag:debug.config") for k in r.cache_inputs())
    assert r.label.startswith("linux-6.6.30-") and len(r.label.split("-")[-1]) == 8


def test_build_recipe_label_changes_with_fragment_content(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    a = build_recipe(settings, version="6.6.30", workspace=tmp_path,
                     fragments=[_frag(tmp_path, "f.config", "CONFIG_A=y\n")])
    b = build_recipe(settings, version="6.6.30", workspace=tmp_path,
                     fragments=[_frag(tmp_path, "f.config", "CONFIG_B=y\n")])
    assert a.label != b.label


def test_build_recipe_label_embeds_kernel_tag(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64", "kernel_tag": "gef"}})
    r = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
    assert r.label.startswith("linux-6.6.30-gef-")


def test_rootfs_recipe_label(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "rootfs": {"distribution": "bookworm"}})
    r = rootfs_recipe(settings)
    assert isinstance(r, RootfsRecipe)
    assert r.label.startswith("rootfs-arm64-bookworm-") and len(r.label.split("-")[-1]) == 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_recipes.py -v`
Expected: FAIL with `ImportError: cannot import name 'BuildRecipe'`.

- [ ] **Step 3: Add recipes to `src/likedbg/cache.py`** (append; add the imports at the top):

```python
# add to the top-of-file imports:
import hashlib
from dataclasses import dataclass
from pathlib import Path

from likedbg.config import Settings
from likedbg.stages.download import resolve_version
from likedbg.toolchain import resolve_toolchain


@dataclass(frozen=True)
class BuildRecipe:
    version: str
    arch: str
    compiler: str
    make_vars: tuple[tuple[str, str], ...]
    frag_hashes: tuple[tuple[str, str], ...]
    fragments: tuple[str, ...]
    kernel_tag: str = ""

    def env(self) -> dict[str, str]:
        return dict(self.make_vars)

    def cache_inputs(self) -> dict[str, str]:
        inputs = {"version": self.version, "arch": self.arch, "compiler": self.compiler}
        inputs.update({f"frag:{name}": h for name, h in self.frag_hashes})
        return inputs

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        tag = f"-{slug(self.kernel_tag)}" if self.kernel_tag else ""
        return f"linux-{slug(self.version)}{tag}-{short_hash(self.key)}"


@dataclass(frozen=True)
class RootfsRecipe:
    arch: str
    distribution: str
    hostname: str

    def cache_inputs(self) -> dict[str, str]:
        return {"arch": self.arch, "distribution": self.distribution, "hostname": self.hostname}

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        return f"rootfs-{slug(self.arch)}-{slug(self.distribution)}-{short_hash(self.key)}"


def build_recipe(settings: Settings, *, version: str, workspace: Path, fragments: list[str]) -> BuildRecipe:
    tc = resolve_toolchain(settings.kernel_builder.compiler, settings.general.arch)
    frag_hashes = sorted(
        (Path(rel).name, hashlib.sha256((workspace / rel).read_bytes()).hexdigest()) for rel in fragments
    )
    return BuildRecipe(
        version=version,
        arch=settings.general.arch,
        compiler=settings.kernel_builder.compiler,
        make_vars=tuple(sorted(tc.make_vars.items())),
        frag_hashes=tuple(frag_hashes),
        fragments=tuple(fragments),
        kernel_tag=settings.general.kernel_tag,
    )


def rootfs_recipe(settings: Settings) -> RootfsRecipe:
    return RootfsRecipe(
        arch=settings.general.arch,
        distribution=settings.rootfs.distribution,
        hostname=settings.rootfs.hostname,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_recipes.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_recipes.py
git commit -m "feat(cache): BuildRecipe/RootfsRecipe + builders + Labels (no-drift seam)"
```

---

### Task 3: Manifest registry (atomic write / read)

The host-side record. Manifest present ⇒ cached. Written atomically on success only.

**Files:**
- Modify: `src/likedbg/cache.py`
- Create: `tests/test_cache_manifest.py`

**Interfaces:**
- Produces:
  - `cache.Manifest` (frozen) with `kind: str`, `label: str`, `key: str`, `version: str`, `arch: str`, `storage_mode: str`, `inputs: dict[str, str]`, `paths: dict[str, str]`, `created_at: str = ""`, `size_bytes: int = 0`.
  - `cache.manifest_path(workspace: Path, kind: str, label: str) -> Path` — `<ws>/artifacts/cache/<kind>s/<label>.json`.
  - `cache.manifest_exists(workspace, kind, label) -> bool`.
  - `cache.write_manifest(workspace, manifest) -> Path` — atomic (temp + `os.replace`).
  - `cache.load_manifest(workspace, kind, label) -> Manifest` — raises `CacheError` if absent or malformed.

- [ ] **Step 1: Write the failing test** — create `tests/test_cache_manifest.py`:

```python
import pytest

from likedbg.cache import Manifest, load_manifest, manifest_exists, manifest_path, write_manifest
from likedbg.errors import CacheError


def _m() -> Manifest:
    return Manifest(
        kind="build", label="linux-6.6.30-gef-a1b2c3d4", key="deadbeef", version="6.6.30",
        arch="arm64", storage_mode="volume", inputs={"version": "6.6.30"},
        paths={"kernel_root": "/ksrc/linux-6.6.30-gef-a1b2c3d4"},
    )


def test_manifest_path_layout(tmp_path):
    p = manifest_path(tmp_path, "build", "linux-6.6.30-gef-a1b2c3d4")
    assert p == tmp_path / "artifacts" / "cache" / "builds" / "linux-6.6.30-gef-a1b2c3d4.json"


def test_write_then_load_roundtrip(tmp_path):
    assert manifest_exists(tmp_path, "build", _m().label) is False
    write_manifest(tmp_path, _m())
    assert manifest_exists(tmp_path, "build", _m().label) is True
    loaded = load_manifest(tmp_path, "build", _m().label)
    assert loaded == _m()


def test_load_absent_raises_cacheerror(tmp_path):
    with pytest.raises(CacheError):
        load_manifest(tmp_path, "build", "nope")


def test_load_malformed_raises_cacheerror(tmp_path):
    p = manifest_path(tmp_path, "build", "bad")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json")
    with pytest.raises(CacheError):
        load_manifest(tmp_path, "build", "bad")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_manifest.py -v`
Expected: FAIL with `ImportError: cannot import name 'Manifest'`.

- [ ] **Step 3: Add the Manifest registry to `src/likedbg/cache.py`** (append; add `import json`, `import os`, `from dataclasses import field` to the top imports — `json`/`dataclass` are already imported from earlier tasks, add `os` and `field`):

```python
from dataclasses import dataclass, field  # widen the existing dataclass import
import os  # add to top imports

from likedbg.errors import CacheError  # add to top imports


@dataclass(frozen=True)
class Manifest:
    kind: str
    label: str
    key: str
    version: str
    arch: str
    storage_mode: str
    inputs: dict[str, str] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    size_bytes: int = 0


def manifest_path(workspace: Path, kind: str, label: str) -> Path:
    return workspace / "artifacts" / "cache" / f"{kind}s" / f"{label}.json"


def manifest_exists(workspace: Path, kind: str, label: str) -> bool:
    return manifest_path(workspace, kind, label).exists()


def write_manifest(workspace: Path, manifest: Manifest) -> Path:
    path = manifest_path(workspace, manifest.kind, manifest.label)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest.__dict__, indent=2, sort_keys=True))
    os.replace(tmp, path)  # atomic on the same filesystem
    return path


def load_manifest(workspace: Path, kind: str, label: str) -> Manifest:
    path = manifest_path(workspace, kind, label)
    if not path.exists():
        raise CacheError(f"no cached {kind} labelled {label!r}", remedy="run `start_kgdb --list`")
    try:
        data = json.loads(path.read_text())
        return Manifest(**data)
    except (ValueError, TypeError) as exc:
        raise CacheError(f"corrupt manifest {path}", remedy=f"`start_kgdb --clean {label}` and rebuild") from exc
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_manifest.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_manifest.py
git commit -m "feat(cache): Manifest registry with atomic write + typed load"
```

---

### Task 4: Storage-mode-aware location resolution

`locations()` maps a Label + storage mode to the concrete footprint (paths + the gdb mount source) so every consumer is mode-agnostic.

**Files:**
- Modify: `src/likedbg/cache.py`
- Create: `tests/test_cache_locations.py`

**Interfaces:**
- Produces:
  - `cache.Locations` (frozen): `kernel_root: str` (container view of the tree), `vmlinux_in_tree: str`, `image_in_tree: str`, `image_host: str` (host export path; empty in bind mode), `gdb_mount_source: str`, `gdb_mount_type: str` (`"volume"`/`"bind"`), `gdb_vmlinux: str` (path the gdb container reads).
  - `cache.locations(label: str, *, arch: str, storage_mode: str, workspace: Path, volume: str = "likedbg_ksrc") -> Locations`.
- Notes: image filename is `bzImage` for x86_64 else `Image`. Volume mode: tree in the named volume at `/ksrc/<label>`, host export at `<ws>/artifacts/<label>/Image`, gdb mounts the named volume. Bind mode: tree at host `<ws>/artifacts/builds/<label>` (container-visible at `/ksrc/<label>` via its own mount), no host export, gdb bind-mounts the host tree dir.

- [ ] **Step 1: Write the failing test** — create `tests/test_cache_locations.py`:

```python
from pathlib import Path

from likedbg.cache import locations


def test_volume_mode_footprint():
    loc = locations("linux-6.6.30-gef-a1b2c3d4", arch="arm64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.kernel_root == "/ksrc/linux-6.6.30-gef-a1b2c3d4"
    assert loc.image_in_tree == "/ksrc/linux-6.6.30-gef-a1b2c3d4/arch/arm64/boot/Image"
    assert loc.image_host == "/ws/artifacts/linux-6.6.30-gef-a1b2c3d4/Image"
    assert loc.gdb_mount_source == "likedbg_ksrc"
    assert loc.gdb_mount_type == "volume"
    assert loc.gdb_vmlinux == "/ksrc/linux-6.6.30-gef-a1b2c3d4/vmlinux"


def test_bind_mode_footprint_has_no_host_export():
    loc = locations("linux-6.6.30-gef-a1b2c3d4", arch="arm64", storage_mode="bind", workspace=Path("/ws"))
    assert loc.image_host == ""
    assert loc.gdb_mount_type == "bind"
    assert loc.gdb_mount_source == "/ws/artifacts/builds/linux-6.6.30-gef-a1b2c3d4"


def test_x86_uses_bzimage():
    loc = locations("linux-6.6.30-x-deadbeef", arch="x86_64", storage_mode="volume", workspace=Path("/ws"))
    assert loc.image_in_tree.endswith("/arch/x86_64/boot/bzImage")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cache_locations.py -v`
Expected: FAIL with `ImportError: cannot import name 'locations'`.

- [ ] **Step 3: Add `Locations` + `locations()` to `src/likedbg/cache.py`** (append):

```python
@dataclass(frozen=True)
class Locations:
    kernel_root: str
    vmlinux_in_tree: str
    image_in_tree: str
    image_host: str
    gdb_mount_source: str
    gdb_mount_type: str
    gdb_vmlinux: str


def locations(
    label: str, *, arch: str, storage_mode: str, workspace: Path, volume: str = "likedbg_ksrc"
) -> Locations:
    image_name = "bzImage" if arch == "x86_64" else "Image"
    container_root = f"/ksrc/{label}"
    image_in_tree = f"{container_root}/arch/{arch}/boot/{image_name}"
    if storage_mode == "volume":
        return Locations(
            kernel_root=container_root,
            vmlinux_in_tree=f"{container_root}/vmlinux",
            image_in_tree=image_in_tree,
            image_host=str(workspace / "artifacts" / label / image_name.replace("bzImage", "Image")),
            gdb_mount_source=volume,
            gdb_mount_type="volume",
            gdb_vmlinux=f"{container_root}/vmlinux",
        )
    host_tree = workspace / "artifacts" / "builds" / label
    return Locations(
        kernel_root=container_root,
        vmlinux_in_tree=f"{container_root}/vmlinux",
        image_in_tree=image_in_tree,
        image_host="",
        gdb_mount_source=str(host_tree),
        gdb_mount_type="bind",
        gdb_vmlinux="/ksrc/vmlinux",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cache_locations.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_locations.py
git commit -m "feat(cache): storage-mode-aware location resolution"
```

---

### Task 5: Context fields + cache-aware Unpack

Thread Labels through the context; make Unpack reuse the keyed tree or produce it (wipe-before-produce).

**Files:**
- Modify: `src/likedbg/pipeline.py` (add two context fields)
- Modify: `src/likedbg/stages/unpack.py`
- Modify: `tests/test_stage_unpack.py`

**Interfaces:**
- Consumes: `cache.manifest_exists`, `cache.locations`, `cache.Manifest`, `cache.write_manifest`; `PipelineContext.build_label`.
- Produces: `PipelineContext.build_label: str | None = None`, `PipelineContext.rootfs_label: str | None = None`. Unpack sets `ctx.kernel_root` (a `Path` of the container-view keyed root) on both reuse and produce.

- [ ] **Step 1: Write the failing test** — append to `tests/test_stage_unpack.py` (reuse its existing `FakeC`/`_ctx` helpers; if absent, mirror the fake from `tests/test_stage_rootfs.py`):

```python
from pathlib import Path

from likedbg.cache import Manifest, write_manifest
from likedbg.stages.unpack import UnpackStage


def test_unpack_reuses_when_manifest_present(tmp_path):
    label = "linux-6.6.30-gef-a1b2c3d4"
    write_manifest(tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30",
                                      arch="arm64", storage_mode="volume",
                                      paths={"kernel_root": f"/ksrc/{label}"}))
    c = _UnpackFakeC()
    ctx = _ctx(tmp_path)              # storage_mode="volume", kernel_archive set
    ctx.build_label = label
    out = UnpackStage(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
    assert str(out.kernel_root) == f"/ksrc/{label}"
    assert c.started is False         # no container work on reuse


def test_unpack_wipes_then_extracts_on_miss(tmp_path):
    c = _UnpackFakeC()
    ctx = _ctx(tmp_path)
    ctx.build_label = "linux-6.6.30-gef-a1b2c3d4"
    UnpackStage(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
    joined = " ; ".join(c.execs)
    assert "rm -rf /ksrc/linux-6.6.30-gef-a1b2c3d4" in joined
    assert "tar -C /ksrc/linux-6.6.30-gef-a1b2c3d4 --strip-components=1" in joined
```

Add the fake + ctx helper at the top of the appended block (only if the file lacks them):

```python
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext


class _UnpackFakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []
        self.started = False

    def run_detached(self, image, **kwargs):
        self.started = True
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode="volume", gdbstub_addr="x", ssh_addr="x")
    ctx = PipelineContext(settings=settings, host=host)
    (tmp_path / "kernels").mkdir(parents=True, exist_ok=True)
    archive = tmp_path / "kernels" / "linux-6.6.30.tar.xz"
    archive.write_bytes(b"x")
    ctx.kernel_archive = archive
    return ctx
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_unpack.py -k "reuse or wipe" -v`
Expected: FAIL — `PipelineContext` has no `build_label` (AttributeError) / behavior missing.

- [ ] **Step 3: Add the context fields** in `src/likedbg/pipeline.py` (`PipelineContext` dataclass), after `kernel_image`:

```python
    build_label: str | None = None
    rootfs_label: str | None = None
```

- [ ] **Step 4: Rewrite `UnpackStage.run`** in `src/likedbg/stages/unpack.py` to be cache-aware. Replace the class body's `run` (keep imports; add `from pathlib import Path`, and `from likedbg import cache`):

```python
    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None:
            raise UnpackError("no build label in context", remedy="the CLI must set ctx.build_label")
        label = ctx.build_label
        if cache.manifest_exists(self._workspace, "build", label):
            ctx.kernel_root = Path(f"/ksrc/{label}") if ctx.host.storage_mode == "volume" else Path(f"/ksrc/{label}")
            return ctx
        if ctx.kernel_archive is None:
            raise UnpackError("no kernel archive in context", remedy="run the Download stage first")
        rel = ctx.kernel_archive.relative_to(self._workspace)
        archive_in = f"{_MOUNT}/{rel}"
        keyed = f"/ksrc/{label}"
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"rm -rf {keyed}")
            self._c.exec(container, f"mkdir -p {keyed}")
            self._c.exec(container, f"tar -C {keyed} --strip-components=1 -xf {archive_in}")
        finally:
            self._c.stop(container)
        ctx.kernel_root = Path(keyed)
        return ctx
```

(Keep the original `relative_to` `ValueError` guard from the existing code by wrapping the `rel = …` line in the existing try/except `UnpackError` block.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_unpack.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/pipeline.py src/likedbg/stages/unpack.py tests/test_stage_unpack.py
git commit -m "feat(cache): cache-aware Unpack (reuse via manifest, wipe-before-produce)"
```

---

### Task 6: Cache-aware Build (from BuildRecipe)

Build reuses the keyed tree or compiles it **from the recipe**, then writes the build Manifest.

**Files:**
- Modify: `src/likedbg/stages/build.py`
- Modify: `tests/test_stage_build.py`

**Interfaces:**
- Consumes: `PipelineContext.build_label`; `cache.manifest_exists`, `cache.load_manifest`, `cache.locations`, `cache.Manifest`, `cache.write_manifest`, `cache.build_recipe`. The CLI passes the `BuildRecipe` to `BuildStage` via constructor (`recipe: BuildRecipe`).
- Produces: sets `ctx.vmlinux` (container path) + `ctx.kernel_image` (in-tree container path); writes a `build` Manifest with `paths` from `locations()`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_stage_build.py`:

```python
from likedbg.cache import BuildRecipe, manifest_exists
from likedbg.stages.build import BuildStage


def _recipe():
    return BuildRecipe(version="6.6.30", arch="arm64", compiler="clang",
                       make_vars=(("ARCH", "arm64"), ("LLVM", "1")),
                       frag_hashes=(), fragments=("configs/fragments/debug.config",))


def test_build_reuses_when_manifest_present(tmp_path):
    from likedbg.cache import Manifest, write_manifest
    label = "linux-6.6.30-a1b2c3d4"
    write_manifest(tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30",
                                      arch="arm64", storage_mode="volume",
                                      paths={"vmlinux_in_tree": f"/ksrc/{label}/vmlinux",
                                             "image_in_tree": f"/ksrc/{label}/arch/arm64/boot/Image"}))
    c = _BuildFakeC()
    ctx = _ctx(tmp_path); ctx.build_label = label; ctx.kernel_root = None
    out = BuildStage(c, recipe=_recipe(), workspace=tmp_path, kernel_volume="likedbg_ksrc").run(ctx)
    assert str(out.vmlinux) == f"/ksrc/{label}/vmlinux"
    assert c.started is False


def test_build_compiles_with_recipe_make_vars_then_writes_manifest(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    ctx = _ctx(tmp_path); ctx.build_label = label; ctx.kernel_root = None
    BuildStage(c, recipe=_recipe(), workspace=tmp_path, kernel_volume="likedbg_ksrc").run(ctx)
    allcmds = " ; ".join(c.execs)
    assert "ARCH=arm64" in allcmds and "LLVM=1" in allcmds          # from the recipe, not settings
    assert "make" in allcmds and "all" in allcmds
    assert manifest_exists(tmp_path, "build", label) is True
```

Add a `_BuildFakeC` (records `execs`, `started`) and `_ctx` near the new tests, mirroring Task 5's fake (arch=arm64, storage_mode="volume").

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_build.py -k "reuse or recipe" -v`
Expected: FAIL — `BuildStage.__init__` has no `recipe` parameter.

- [ ] **Step 3: Rewrite `BuildStage`** in `src/likedbg/stages/build.py` to take a `recipe` and be cache-aware:

```python
from pathlib import Path

from likedbg import cache
from likedbg.cache import BuildRecipe


class BuildStage:
    name = "build"

    def __init__(self, container, *, recipe: BuildRecipe, workspace: Path, kernel_volume: str) -> None:
        self._c = container
        self._recipe = recipe
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx):  # never skip — reuse is decided in run()
        return False

    def run(self, ctx):
        if ctx.build_label is None:
            raise BuildError("no build label in context", remedy="the CLI must set ctx.build_label")
        label = ctx.build_label
        loc = cache.locations(label, arch=self._recipe.arch, storage_mode=ctx.host.storage_mode,
                              workspace=self._workspace, volume=self._volume)
        if cache.manifest_exists(self._workspace, "build", label):
            m = cache.load_manifest(self._workspace, "build", label)
            ctx.vmlinux = Path(m.paths["vmlinux_in_tree"])
            ctx.kernel_image = Path(m.paths["image_in_tree"])
            return ctx
        root = loc.kernel_root
        env = self._recipe.env()
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(self._image_or_default(), volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, make_command(env, "mrproper"), workdir=root)
            self._c.exec(container, make_command(env, "defconfig"), workdir=root)
            if self._recipe.fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._recipe.fragments)
                self._c.exec(container,
                             f"./scripts/kconfig/merge_config.sh -m .config {frags} && {make_command(env, 'olddefconfig')}",
                             workdir=root)
            self._c.exec(container, make_command(env, "all"), workdir=root)
        finally:
            self._c.stop(container)
        ctx.vmlinux = Path(loc.vmlinux_in_tree)
        ctx.kernel_image = Path(loc.image_in_tree)
        cache.write_manifest(self._workspace, cache.Manifest(
            kind="build", label=label, key=self._recipe.key, version=self._recipe.version,
            arch=self._recipe.arch, storage_mode=ctx.host.storage_mode,
            inputs=self._recipe.cache_inputs(),
            paths={"kernel_root": loc.kernel_root, "vmlinux_in_tree": loc.vmlinux_in_tree,
                   "image_in_tree": loc.image_in_tree, "image_host": loc.image_host,
                   "gdb_mount_source": loc.gdb_mount_source, "gdb_mount_type": loc.gdb_mount_type,
                   "gdb_vmlinux": loc.gdb_vmlinux}))
        return ctx
```

Add the kbuilder image as a constructor arg instead of `_image_or_default()` — keep the existing `kbuilder_image` parameter: change `__init__` to also accept `kbuilder_image: str` and store `self._image`, then use `self._image` in `run_detached`. (Drop the `_image_or_default()` placeholder.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_build.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/build.py tests/test_stage_build.py
git commit -m "feat(cache): cache-aware Build from BuildRecipe + build manifest"
```

---

### Task 7: Cache-aware Rootfs (from RootfsRecipe)

Rootfs reuses its keyed image (free host `exists()` check) or builds it from the recipe and writes the rootfs Manifest.

**Files:**
- Modify: `src/likedbg/stages/rootfs.py`
- Modify: `tests/test_stage_rootfs.py`

**Interfaces:**
- Consumes: `PipelineContext.rootfs_label`; `cache.manifest_exists/load_manifest/write_manifest/Manifest/rootfs_recipe`. Constructor takes `recipe: RootfsRecipe`.
- Produces: image at `<ws>/artifacts/rootfs/<rootfs_label>.img`; sets `ctx.rootfs_image` to that host path; writes a `rootfs` Manifest. On reuse, if the recorded image file is missing → `CacheError`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_stage_rootfs.py`:

```python
import pytest

from likedbg.cache import Manifest, RootfsRecipe, manifest_exists, write_manifest
from likedbg.errors import CacheError


def _rrecipe():
    return RootfsRecipe(arch="arm64", distribution="bookworm", hostname="LIKE-DBG")


def test_rootfs_reuses_present_image_without_rebuild(tmp_path):
    label = _rrecipe().label
    img = tmp_path / "artifacts" / "rootfs" / f"{label}.img"
    img.parent.mkdir(parents=True, exist_ok=True); img.write_bytes(b"img")
    write_manifest(tmp_path, Manifest(kind="rootfs", label=label, key=_rrecipe().key,
                                      version="", arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(img)}))
    c = FakeC()
    ctx = _ctx(tmp_path); ctx.rootfs_label = label
    out = RootfsStage(c, recipe=_rrecipe(), workspace=tmp_path).run(ctx)
    assert out.rootfs_image == img
    assert c.run_kwargs is None


def test_rootfs_reuse_missing_image_raises(tmp_path):
    label = _rrecipe().label
    write_manifest(tmp_path, Manifest(kind="rootfs", label=label, key="k", version="",
                                      arch="arm64", storage_mode="volume",
                                      paths={"image_host": str(tmp_path / "gone.img")}))
    ctx = _ctx(tmp_path); ctx.rootfs_label = label
    with pytest.raises(CacheError):
        RootfsStage(FakeC(), recipe=_rrecipe(), workspace=tmp_path).run(ctx)


def test_rootfs_builds_and_writes_manifest_on_miss(tmp_path):
    c = FakeC()
    ctx = _ctx(tmp_path); ctx.rootfs_label = _rrecipe().label
    out = RootfsStage(c, recipe=_rrecipe(), workspace=tmp_path).run(ctx)
    assert out.rootfs_image == tmp_path / "artifacts" / "rootfs" / f"{_rrecipe().label}.img"
    assert manifest_exists(tmp_path, "rootfs", _rrecipe().label) is True
    assert c.run_kwargs["privileged"] is True
```

(The existing `FakeC`/`_ctx` remain; `_ctx` must set `storage_mode="volume"`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_rootfs.py -k "reuse or writes_manifest" -v`
Expected: FAIL — `RootfsStage.__init__` has no `recipe`.

- [ ] **Step 3: Rewrite `RootfsStage`** in `src/likedbg/stages/rootfs.py`:

```python
from likedbg import cache
from likedbg.cache import RootfsRecipe
from likedbg.errors import CacheError, RootfsError


def rootfs_target(workspace, label):
    return workspace / "artifacts" / "rootfs" / f"{label}.img"


class RootfsStage:
    name = "rootfs"

    def __init__(self, container, *, recipe: RootfsRecipe, workspace) -> None:
        self._c = container
        self._recipe = recipe
        self._workspace = workspace

    def should_skip(self, ctx):
        return False

    def run(self, ctx):
        if ctx.rootfs_label is None:
            raise RootfsError("no rootfs label in context", remedy="the CLI must set ctx.rootfs_label")
        label = ctx.rootfs_label
        target = rootfs_target(self._workspace, label)
        if cache.manifest_exists(self._workspace, "rootfs", label):
            m = cache.load_manifest(self._workspace, "rootfs", label)
            img = Path(m.paths["image_host"])
            if not img.exists():
                raise CacheError(f"cached rootfs {label} image is gone",
                                 remedy=f"`start_kgdb --clean {label}` and rebuild")
            ctx.rootfs_image = img
            return ctx
        target.parent.mkdir(parents=True, exist_ok=True)
        qemu_arch = "aarch64" if self._recipe.arch == "arm64" else "x86_64"
        cmd = (f"/bin/bash -lc '. /home/user/rootfs.sh -n {target.name} -a {qemu_arch} "
               f"-d {self._recipe.distribution} -u user -h {self._recipe.hostname}'")
        try:
            container = self._c.run_detached(self._image, volumes={str(target.parent): {"bind": _MOUNT, "mode": "rw"}},
                                             privileged=True, detach=True, command=cmd)
        except Exception as exc:  # noqa: BLE001
            raise RootfsError("failed to start rootfs build container", remedy="check the rootfs image exists") from exc
        for line in container.logs(stream=True, follow=True):
            _ = line
        self._c.stop(container)
        ctx.rootfs_image = target
        cache.write_manifest(self._workspace, cache.Manifest(
            kind="rootfs", label=label, key=self._recipe.key, version="", arch=self._recipe.arch,
            storage_mode=ctx.host.storage_mode, inputs=self._recipe.cache_inputs(),
            paths={"image_host": str(target)}))
        return ctx
```

Keep the existing `rootfs_image` constructor parameter name `rootfs_image` for the kbuilder image tag — rename to keep it: add `rootfs_image: str` to `__init__` and store `self._image` (the test passes it positionally via `FakeC`? No — update the test constructor calls to `RootfsStage(c, recipe=…, workspace=…)` and add `rootfs_image="like_rootfs"` where the real image is needed). For the unit tests the image tag is unused by `FakeC`, so include `rootfs_image="like_rootfs"` in the test constructor calls.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_rootfs.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/rootfs.py tests/test_stage_rootfs.py
git commit -m "feat(cache): cache-aware Rootfs from RootfsRecipe + rootfs manifest"
```

---

### Task 8: Cache-aware Export (host check + produce-time volume verify)

Export copies the keyed Image to the host per build (volume mode), verifying the in-volume artifacts exist when it produces.

**Files:**
- Modify: `src/likedbg/stages/export.py`
- Modify: `tests/test_stage_export.py`

**Interfaces:**
- Consumes: `PipelineContext.build_label`, `ctx.kernel_image` (in-tree container path), `cache.locations`. Constructor unchanged (`container, *, kernel_volume, workspace`).
- Produces: copies in-tree Image → `<ws>/artifacts/<label>/Image`; sets `ctx.kernel_image` to that host `Path`. Before copying, `test -e` the in-volume `vmlinux` + Image → `CacheError` if missing. Skips the copy if the host Image already exists. `should_skip` unchanged (skip when `storage_mode != "volume"`).

- [ ] **Step 1: Write the failing test** — append to `tests/test_stage_export.py`:

```python
from pathlib import Path

from likedbg.stages.export import ArtifactExporter


def test_export_verifies_then_copies_and_sets_host_image(tmp_path):
    c = _ExportFakeC()                 # exec records cmds; first test -e returns ok
    ctx = _ctx(tmp_path)               # storage_mode="volume"
    ctx.build_label = "linux-6.6.30-a1b2c3d4"
    ctx.kernel_root = Path("/ksrc/linux-6.6.30-a1b2c3d4")
    ctx.vmlinux = Path("/ksrc/linux-6.6.30-a1b2c3d4/vmlinux")
    ctx.kernel_image = Path("/ksrc/linux-6.6.30-a1b2c3d4/arch/arm64/boot/Image")
    out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(ctx)
    assert out.kernel_image == tmp_path / "artifacts" / "linux-6.6.30-a1b2c3d4" / "Image"
    allcmds = " ; ".join(c.execs)
    assert "test -e /ksrc/linux-6.6.30-a1b2c3d4/vmlinux" in allcmds
    assert "cp /ksrc/linux-6.6.30-a1b2c3d4/arch/arm64/boot/Image" in allcmds
```

Add `_ExportFakeC` (records `execs`, `exec` returns ok) + `_ctx` (arch=arm64, storage_mode="volume").

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_export.py -k verifies -v`
Expected: FAIL — host image path is the old `artifacts/<kernel_root.name>/Image`, no `test -e` issued.

- [ ] **Step 3: Rewrite `ArtifactExporter.run`** in `src/likedbg/stages/export.py` to key by `ctx.build_label` and verify before copy:

```python
    def run(self, ctx):
        if ctx.build_label is None or ctx.kernel_image is None:
            raise BuildError("missing build label / image in context", remedy="run Build first")
        label = ctx.build_label
        out_dir = self._workspace / "artifacts" / label
        host_image = out_dir / "Image"
        if host_image.exists():
            ctx.kernel_image = host_image
            return ctx
        out_dir.mkdir(parents=True, exist_ok=True)
        image_in_tree = str(ctx.kernel_image)
        vmlinux_in_tree = f"/ksrc/{label}/vmlinux"
        volumes = {
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "ro"},
            str(out_dir): {"bind": _OUT_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"test -e {vmlinux_in_tree}")
            self._c.exec(container, f"test -e {image_in_tree}")
            self._c.exec(container, f"cp {image_in_tree} {_OUT_MOUNT}/Image")
        finally:
            self._c.stop(container)
        ctx.kernel_image = host_image
        return ctx
```

(If `test -e` fails, `ContainerService.exec` raises `ContainerError`; wrap the two `test -e` calls so a failure re-raises as `CacheError` with remedy `--clean {label}`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_export.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/export.py tests/test_stage_export.py
git commit -m "feat(cache): cache-aware Export (per-label, verify in-volume artifacts)"
```

---

### Task 9: CLI default threading + gdb mount source + `--force-rebuild`

Derive recipes/labels, thread them through the pipeline, drive the gdb pane with the cache-resolved mount source (fixing the Plan-4 hardcoded volume), and add `--force-rebuild`.

**Files:**
- Modify: `src/likedbg/cli.py`
- Modify: `src/likedbg/launchers.py`
- Modify: `tests/test_cli.py`, `tests/test_launchers.py`

**Interfaces:**
- Consumes: `cache.build_recipe`, `cache.rootfs_recipe`, `cache.locations`; `stages.download.resolve_version`.
- Produces:
  - `launchers.gdb_pane_command(gdb_args, *, image, mount_source)` — `-v <mount_source>:/ksrc:ro` (named volume **or** host dir).
  - `cli.build_pipeline(... , build_recipe, rootfs_recipe, force_rebuild: bool=False)` — wires `BuildStage(recipe=…)`, `RootfsStage(recipe=…)`, the gdb closure using `locations(...).gdb_mount_source`; sets `ctx.build_label`/`ctx.rootfs_label`.
  - `cli.main` parses `--force-rebuild` (when set, delete the build Manifest before running so Build recompiles).

- [ ] **Step 1: Write the failing test** — update `tests/test_launchers.py` (rename param) and append to `tests/test_cli.py`:

```python
# tests/test_launchers.py — replace the gdb test's kwarg name:
def test_gdb_pane_command_wraps_docker_run_with_addhost_and_volume():
    cmd = gdb_pane_command(["gdb-multiarch", "-q", "/ksrc/x/vmlinux", "-ex", "hbreak start_kernel"],
                           image="like_debugger:latest", mount_source="likedbg_ksrc")
    assert cmd.startswith("docker run --rm")
    assert "-v likedbg_ksrc:/ksrc:ro" in cmd
    assert "hbreak start_kernel" in cmd


def test_gdb_pane_command_accepts_bind_dir_mount_source():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/ws/artifacts/builds/x")
    assert "-v /ws/artifacts/builds/x:/ksrc:ro" in cmd
```

```python
# tests/test_cli.py — replace the existing build_pipeline call to pass recipes:
from likedbg.cache import build_recipe, rootfs_recipe
from likedbg.config import Settings


def test_build_pipeline_includes_all_stage_names(tmp_path):
    settings = Settings.model_validate({"general": {"arch": "arm64"}})
    br = build_recipe(settings, version="6.6.30", workspace=tmp_path, fragments=[])
    rr = rootfs_recipe(settings)
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: None)
    pipe = build_pipeline(ContainerService(SimpleNamespace()), session, workspace=tmp_path,
                          kernel_volume="likedbg_ksrc", dl_dir=tmp_path / "kernels",
                          debugger_image="like_debugger:latest", ext="gef", panes=(1, 2),
                          build_recipe=br, rootfs_recipe=rr)
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_launchers.py tests/test_cli.py -v`
Expected: FAIL — `gdb_pane_command` has no `mount_source`; `build_pipeline` has no `build_recipe`.

- [ ] **Step 3: Update `launchers.gdb_pane_command`** in `src/likedbg/launchers.py`:

```python
def gdb_pane_command(gdb_args: list[str], *, image: str, mount_source: str) -> str:
    docker = f"docker run --rm -it --add-host=host.docker.internal:host-gateway -v {mount_source}:/ksrc:ro {image} "
    return docker + shlex.join(gdb_args)
```

- [ ] **Step 4: Update `cli.build_pipeline` and `cli.main`** in `src/likedbg/cli.py`:

`build_pipeline` — accept `build_recipe: BuildRecipe`, `rootfs_recipe: RootfsRecipe`; construct `BuildStage(container, recipe=build_recipe, kbuilder_image="like_kbuilder_arm64:latest", workspace=workspace, kernel_volume=kernel_volume)` and `RootfsStage(container, recipe=rootfs_recipe, rootfs_image="like_rootfs:latest", workspace=workspace)`; the `run_gdb` closure resolves the mount source:

```python
    def run_gdb(args: list[str]) -> None:
        loc = cache.locations(build_recipe.label, arch=build_recipe.arch,
                              storage_mode="volume", workspace=workspace, volume=kernel_volume)
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, mount_source=loc.gdb_mount_source))
```

Set `ctx` labels before running (in `main`): after building recipes, `ctx.build_label = build_recipe.label`, `ctx.rootfs_label = rootfs_recipe.label` (pass labels by setting them on the `PipelineContext` constructed in `main`).

`main` — after `load_settings`, build the recipes and labels:

```python
    version = resolve_version(settings.kernel_dl)
    br = build_recipe(settings, version=version, workspace=workspace, fragments=_FRAGMENTS)
    rr = rootfs_recipe(settings)
    if args.force_rebuild:
        mp = cache.manifest_path(workspace, "build", br.label)
        mp.unlink(missing_ok=True)
    ...
    ctx = PipelineContext(settings=settings, host=host, build_label=br.label, rootfs_label=rr.label)
```

Add `parser.add_argument("--force-rebuild", action="store_true")` and pass `build_recipe=br, rootfs_recipe=rr` to `build_pipeline`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py tests/test_launchers.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/cli.py src/likedbg/launchers.py tests/test_cli.py tests/test_launchers.py
git commit -m "feat(cache): CLI threads recipes/labels; gdb mount source from cache; --force-rebuild"
```

---

### Task 10: `--adopt` — verified migration of the legacy unkeyed build

Import `/ksrc/linux-<version>` into the cache under the active config's Label, hard-refusing on version/compiler mismatch.

**Files:**
- Modify: `src/likedbg/cli.py`
- Create: `src/likedbg/adopt.py`
- Create: `tests/test_adopt.py`

**Interfaces:**
- Produces:
  - `adopt.adopt_legacy_build(container, *, workspace, recipe, volume="likedbg_ksrc") -> str` — verifies version (tree `Makefile`) and compiler family (`.config` `CONFIG_CC_VERSION_TEXT`) against `recipe`, `mv /ksrc/linux-<version> /ksrc/<label>`, writes the build Manifest, returns the label. Mismatch → `CacheError`.
  - `cli.main` parses `--adopt`; when set, run adoption and exit 0.
- Consumes: `ContainerService.exec` (reads Makefile/.config via `cat`/`grep`), `cache.locations`, `cache.write_manifest`.

- [ ] **Step 1: Write the failing test** — create `tests/test_adopt.py`:

```python
import pytest

from likedbg.adopt import adopt_legacy_build
from likedbg.cache import BuildRecipe, manifest_exists
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
            out = f"VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\n" if self._version == "6.6.30" else "VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 0\n"
        elif "CC_VERSION_TEXT" in cmd:
            out = f'CONFIG_CC_VERSION_TEXT="{self._cc}"\n'
        else:
            out = ""
        return SimpleNamespace(exit_code=0, output=out)

    def stop(self, container):
        pass


def _recipe(compiler="clang"):
    return BuildRecipe(version="6.6.30", arch="arm64", compiler=compiler,
                       make_vars=(("ARCH", "arm64"),), frag_hashes=(), fragments=())


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_adopt.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.adopt'`.

- [ ] **Step 3: Create `src/likedbg/adopt.py`**:

```python
"""One-time migration of the legacy unkeyed /ksrc/linux-<version> tree into the Build Cache,
verified against the active config (version + compiler family) before adoption. See spec §4.5."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from likedbg import cache
from likedbg.cache import BuildRecipe
from likedbg.errors import CacheError

_BASE_IMAGE = "like_dbg_base"
_VOLUME_MOUNT = "/ksrc"


def _parse_makefile_version(text: str) -> str:
    fields = {}
    for line in text.splitlines():
        for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
            if line.startswith(key) and "=" in line:
                fields[key] = line.split("=", 1)[1].strip()
    return f"{fields.get('VERSION')}.{fields.get('PATCHLEVEL')}.{fields.get('SUBLEVEL')}"


def adopt_legacy_build(container: Any, *, workspace: Path, recipe: BuildRecipe, volume: str = "likedbg_ksrc") -> str:
    legacy = f"/ksrc/linux-{recipe.version}"
    label = recipe.label
    loc = cache.locations(label, arch=recipe.arch, storage_mode="volume", workspace=workspace, volume=volume)
    c = container.run_detached(_BASE_IMAGE, volumes={volume: {"bind": _VOLUME_MOUNT, "mode": "rw"}},
                               detach=True, tty=True)
    try:
        version = _parse_makefile_version(container.exec(c, f"cat {legacy}/Makefile").output)
        if version != recipe.version:
            raise CacheError(f"legacy tree is {version}, active config is {recipe.version}",
                             remedy="set the matching version, or build fresh")
        cc = container.exec(c, f"grep CC_VERSION_TEXT {legacy}/.config || true").output.lower()
        if recipe.compiler not in cc:
            raise CacheError(f"legacy tree compiler != {recipe.compiler!r} (.config: {cc.strip()})",
                             remedy="set the matching compiler, or build fresh")
        container.exec(c, f"test -e {legacy}/vmlinux")
        container.exec(c, f"mv {legacy} /ksrc/{label}")
    finally:
        container.stop(c)
    cache.write_manifest(workspace, cache.Manifest(
        kind="build", label=label, key=recipe.key, version=recipe.version, arch=recipe.arch,
        storage_mode="volume", inputs=recipe.cache_inputs(),
        paths={"kernel_root": loc.kernel_root, "vmlinux_in_tree": loc.vmlinux_in_tree,
               "image_in_tree": loc.image_in_tree, "image_host": loc.image_host,
               "gdb_mount_source": loc.gdb_mount_source, "gdb_mount_type": loc.gdb_mount_type,
               "gdb_vmlinux": loc.gdb_vmlinux}))
    return label
```

- [ ] **Step 4: Wire `--adopt` into `cli.main`** — add `parser.add_argument("--adopt", action="store_true")`, and after building the docker client + recipes:

```python
    if args.adopt:
        label = adopt_legacy_build(container, workspace=workspace, recipe=br)
        logger.info(f"adopted legacy build as {label}")
        return 0
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_adopt.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/adopt.py src/likedbg/cli.py tests/test_adopt.py
git commit -m "feat(cache): --adopt verified migration of the legacy unkeyed build"
```

---

### Task 11: Live one-command run (EMPIRICAL — adopt → reuse → boot+attach)

> **Empirical gate (the deferred Plan-4 Task 5).** Adopt the existing build, then run `./start_kgdb` and confirm it reuses (no rebuild), boots native HVF in the debuggee pane, and attaches GEF at `start_kernel` in the debugger pane.

- [ ] **Step 1:** Full suite green first: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg`. Expected: all green.
- [ ] **Step 2:** Adopt the existing build: `uv run ./start_kgdb --adopt` (any tmux state; `--adopt` exits before the pipeline). Expected: log `adopted legacy build as linux-6.6.30-…`; `artifacts/cache/builds/<label>.json` exists; the in-volume tree is now `/ksrc/<label>`.
- [ ] **Step 3:** From inside `tmux`, run `uv run ./start_kgdb`. Confirm: Download/Unpack/Build/Rootfs all **reuse** (Build does *not* run `make`); pane 1 shows native QEMU booting under HVF; pane 2 shows GEF attached at the `start_kernel` breakpoint.
- [ ] **Step 4:** Record the working transcript (and any closure/path fixes) in `docs/superpowers/notes/2026-06-23-build-cache-live.md`; fold any wiring fixes back (keeping unit tests green); commit.

---

## Self-Review

- **Spec coverage:** Recipe/key/label (Task 2, ADR-0003) ✓; scope build+rootfs+export-as-footprint (Tasks 6–8) ✓; no-drift via BuildRecipe (Task 6) ✓; manifest atomic write + consistency: wipe-before-produce (Task 5), host-side reuse check (Task 7), Export-time volume verify (Task 8) ✓; storage-mode-aware footprint + manifest resolved paths (Task 4, 6) ✓; gdb mount source from cache, fixing Plan-4 hardcode (Task 9) ✓; `--force-rebuild` (Task 9) ✓; verified `--adopt` (Task 10) ✓; single-active assumption (no locking — nothing added) ✓; live gate (Task 11) ✓. **Deferred to Plan 6 (by design):** `--list`, `--clean`/`--clean-all`, `--use` (selection/management).
- **Placeholder scan:** Tasks 1–10 carry complete code/tests; Task 11 is explicitly empirical. The two `_image_or_default()` / constructor notes in Task 6 and the `RootfsStage` image-tag note in Task 7 instruct the exact constructor parameter to keep — no placeholder logic.
- **Type consistency:** `BuildRecipe`/`RootfsRecipe` fields + `.env()/.cache_inputs()/.key/.label`; `Manifest(kind,label,key,version,arch,storage_mode,inputs,paths,…)`; `locations(label, *, arch, storage_mode, workspace, volume)`; `gdb_pane_command(…, mount_source=…)`; `build_pipeline(…, build_recipe=…, rootfs_recipe=…)`; `adopt_legacy_build(container, *, workspace, recipe, volume)` — used consistently across tasks and tests.
