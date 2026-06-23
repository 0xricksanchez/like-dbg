# Section A — Foundation Hardening (deferred-polish batch) — Design

**Date:** 2026-06-23
**Status:** approved (brainstormed + grilled against CONTEXT.md / ADR-0002 / ADR-0003)
**Branch:** `chore/section-a-hardening` off `dev` → merged **locally** (per ROADMAP: `dev` stays local)

## 1. Context

Plans 5 and 6 (Build Cache + cache management) closed with seven items triaged "defer"
during review. The ROADMAP records them under **§A. Deferred polish**. They are not bugs the
daily-driver hits, but they are real correctness guards, one behavioral cleanup, and a
de-duplication that pays down drift risk before the larger §B foundation-completion work.

This batch clears **all seven** in one cohesive, low-risk branch. The happy path is unchanged;
the only runtime-visible behavior change is container auto-removal.

The seven items, mapped to code:

| # | Item | Site | Nature |
|---|------|------|--------|
| 1 | `remove_cached` ignores `manifest.storage_mode` for builds | `cache.py:208` | correctness guard |
| 2 | Hardcoded image/volume literals duplicated across modules | `cli.py`, `cache.py`, `adopt.py`, `export.py`, `build.py`, `unpack.py` | refactor → shared constants |
| 3 | `_parse_makefile_version` yields `"None.None.None"` on a bad Makefile | `adopt.py:23` | error-handling bug |
| 4 | `export.py` uses literal `/ksrc` instead of a constant | `export.py:46` | consistency nit (subsumed by #2) |
| 5 | `slug` has no docstring/empty-string test; `list_manifests` sort | `cache.py:38,162` | cosmetic |
| 6 | `write_manifest` uses a fixed `.json.tmp` temp name | `cache.py:145` | robustness nit |
| 7 | Stopped-container accumulation (no `auto_remove`) | all 6 `run_detached` callers | behavioral cleanup |

## 2. Decisions (resolved during brainstorm + grill)

- **Scope:** all 7 items, one branch.
- **`auto_remove`:** default `auto_remove=True` in `ContainerService.run_detached`, with a
  docstring documenting the invariant that `run_detached` is for **ephemeral utility
  containers** only. The long-lived Debuggee/Debugger are launched as tmux `docker run`
  pane commands, never via `run_detached`, so the default is correct for every current
  caller. Chosen over folding removal into `stop()` because daemon-driven auto-removal is
  robust to abnormal exit (the Python process dying before a `finally: stop()`).
- **Constants home:** a new `src/likedbg/constants.py` (imports nothing internal → no cycles).
- **`remove_cached` guard:** scoped to the **`kind == "build"` branch only** — that branch is
  the only one that assumes volume storage (it mounts the volume and `rm -rf`s the in-volume
  tree). The rootfs branch merely `unlink`s a host image file and is storage-mode-independent.
- **Glossary:** `Storage mode` (volume/bind) added to `CONTEXT.md` (done inline during the
  grill). No new ADR — none of these decisions clears the hard-to-reverse + surprising +
  real-trade-off bar; the one durable concept is the glossary term, and ADR-0002/0003 already
  cover storage and cache-identity.

## 3. Component design

### 3.1 `src/likedbg/constants.py` (new) — items #2, #4

Single home for the infra literals currently duplicated across six modules:

```python
"""Shared infrastructure literals: image tags, the kernel-source volume, and its mount.

These name the project's Docker images and the named volume that holds kernel source in
Volume mode (see CONTEXT.md → Storage mode, ADR-0002). They are infra identifiers, not
user configuration, so they live here rather than in the Pydantic Settings schema.
"""

KERNEL_VOLUME = "likedbg_ksrc"
VOLUME_MOUNT = "/ksrc"

BASE_IMAGE = "like_dbg_base:latest"
# NOTE: the kbuilder image is clang-universal (cross-compiles any arch); the `_arm64`
# suffix is a legacy misnomer. Revisit the name when x86_64-on-Mac lands (ROADMAP §B).
KBUILDER_IMAGE = "like_kbuilder_arm64:latest"
ROOTFS_IMAGE = "like_rootfs:latest"
DEBUGGER_IMAGE = "like_debugger:latest"
```

Scope decisions:
- `BASE_IMAGE` is normalized to `:latest` (today the code uses bare `like_dbg_base`; Docker
  already implies `:latest`, so this is behavior-equivalent, just consistent with the others).
- Single-use literals are **left in place**: `export.py`'s `_OUT_MOUNT = "/out"` and
  `ContainerService(docker_mnt="/io")` are not duplicated, so hoisting them is churn for no
  payoff (YAGNI).

Callers updated to import from `constants`:
- `cli.py` — `kernel_volume=KERNEL_VOLUME` (×2), `debugger_image=DEBUGGER_IMAGE` (×2),
  `kbuilder_image=KBUILDER_IMAGE`, `rootfs_image=ROOTFS_IMAGE`.
- `cache.py` — drop module-private `_BASE_IMAGE`/`_VOLUME_MOUNT`; default `volume=KERNEL_VOLUME`
  on `locations`/`remove_cached`; build `container_root`/paths from `VOLUME_MOUNT`.
- `adopt.py` — drop `_BASE_IMAGE`/`_VOLUME_MOUNT`; default `volume=KERNEL_VOLUME`; build
  `legacy` and the `mv` destination from `VOLUME_MOUNT`.
- `export.py` — drop `_BASE_IMAGE`/`_VOLUME_MOUNT`; `vmlinux_in_tree` from `VOLUME_MOUNT`
  (this **is** item #4).
- `build.py`, `unpack.py` — drop `_BASE_IMAGE`/`_VOLUME_MOUNT`; reference constants.

All extracted values equal the existing literals verbatim (modulo the `:latest` normalization
on base), so the switch is behavior-preserving. The `/ksrc/...` strings asserted by
`test_cache_remove` and `test_adopt` still match because `VOLUME_MOUNT == "/ksrc"`.

### 3.2 `ContainerService.run_detached` auto_remove — item #7

```python
def run_detached(self, image: str, *, auto_remove: bool = True, **kwargs: Any) -> Any:
    """Run a short-lived utility container detached and return its handle.

    Intended for ephemeral helpers that do work then stop (unpack/build/rootfs/export/
    adopt/cache-removal). `auto_remove=True` (default) lets the daemon delete the container
    once it stops, so stopped containers do not accumulate. Long-lived guests (the Debuggee
    and Debugger) are launched as tmux `docker run` pane commands, NOT through this method.
    """
    return self._client.containers.run(image, auto_remove=auto_remove, **kwargs)
```

Liveness is unchanged: callers run with `tty=True` and no command, so the container stays up
for `exec`; `auto_remove` triggers only on the explicit `stop()` in each caller's `finally`.
Error visibility is preserved because `exec` captures output into `ContainerError` *before*
`stop()` runs, so a failed build still reports its output even though the container is removed.

### 3.3 `remove_cached` storage-mode guard — item #1

Inside the `kind == "build"` branch, before mounting the volume:

```python
if manifest.storage_mode != "volume":
    raise CacheError(
        f"cache removal for {manifest.storage_mode!r}-mode builds is not yet wired",
        remedy="this milestone targets Volume mode; Bind/Linux runtime is gated (see require_volume_mode)",
    )
```

The rootfs branch is untouched (storage-mode-independent). No bind-mode build Manifest can
exist today (the bind runtime is gated off), so this is an honest forward guard, not dead code
with behavior.

### 3.4 `adopt._parse_makefile_version` raises on missing fields — item #3

Replace the silent `"None.None.None"` fallthrough with an explicit error:

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

This turns a confusing downstream `"legacy tree is None.None.None"` mismatch error into a
clear root-cause error at the parse site.

### 3.5 `cache.py` cosmetics — items #5, #6

- `slug` gets a one-line docstring (kebab-slug for Labels; lowercases, collapses non
  `[a-z0-9._-]` runs to `-`, trims leading/trailing `-`).
- `list_manifests` sorts explicitly by `key=lambda p: p.stem` (equivalent to today's
  full-path sort within one directory, but states intent).
- `write_manifest` uses `tempfile.mkstemp(dir=path.parent, suffix=".json.tmp")` → write →
  `os.replace`, for a guaranteed-unique temp (atomic on the same FS via `O_EXCL`).

## 4. Testing strategy

TDD per unit; tests live in `./tests/`.

- **constants (#2/#4):** the full suite staying green after the caller switch is the real
  proof; add a small value-sanity test (constants are non-empty; `BASE_IMAGE` ends `:latest`).
- **`run_detached` auto_remove (#7) — wiring only:** extend `test_container_service.py` to
  assert `run_detached("img")` forwards `auto_remove=True` to `containers.run`, and that an
  explicit `run_detached("img", auto_remove=False)` overrides it. A unit test **cannot** prove
  the daemon actually removes the container — that is a live-gate check (§5).
- **`remove_cached` guard (#1):** new test — a `kind="build"`, `storage_mode="bind"` Manifest
  → `CacheError`; the existing volume-build and rootfs removal tests stay green.
- **`_parse_makefile_version` (#3):** direct unit test — text missing `SUBLEVEL` → `CacheError`;
  valid text → `"6.6.30"`.
- **`slug` (#5):** `slug("") == ""`; an already-clean string round-trips.
- **`write_manifest` (#6):** existing round-trip test still passes (write → `load_manifest`);
  optionally assert no `.json.tmp*` residue remains after a successful write.
- **Gate:** full `pytest`, `mypy --strict`, `ruff check`, `ruff format --check` all green.

## 5. Live-gate verification (behavioral, post-merge on the M5)

Run a real `uv run ./start_kgdb` cycle in volume mode and confirm:
1. **No leftover helper containers:** after the run, `docker ps -a` shows zero stopped
   `like_dbg_base` / `like_kbuilder_arm64` / `like_rootfs` helper containers (item #7 actually
   fixed, not just wired).
2. **Error visibility preserved:** a deliberately-broken build (e.g. an injected bad make var)
   still surfaces full output via `ContainerError`, proving auto-removal did not cost
   post-mortem error output (output is captured pre-`stop()`).

## 6. Sequencing

Each unit is independent and small; `constants` lands first because the others reference it.

1. `constants.py` + switch all callers (subsumes #4)
2. `run_detached` `auto_remove` default + docstring invariant (#7)
3. `remove_cached` build-branch guard (#1)
4. `adopt._parse_makefile_version` raises on missing fields (#3)
5. `cache.py` cosmetics: `slug` docstring, `list_manifests` `p.stem` sort, `write_manifest`
   `mkstemp` (#5, #6)

## 7. Non-goals

- **Renaming the kbuilder image** away from the misleading `_arm64` suffix — flagged in a
  `constants.py` comment, deferred to ROADMAP §B (touches the justfile + forces a rebuild).
- **Bind/Linux cache removal** — the guard refuses it cleanly; implementing the host-tree
  removal path waits until the bind runtime is un-gated (ROADMAP §B).
- **Concurrent same-label runs** — `mkstemp` makes the atomic write self-contained but is
  **not** a concurrency guarantee; two runs building the same Label still collide on the
  in-volume tree and the manifest. Concurrent same-label runs remain unsupported.
- Touching the quarantined legacy `src/*.py` (ruff-excluded).
