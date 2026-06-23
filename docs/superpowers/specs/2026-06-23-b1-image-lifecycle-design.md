# B1 — Image-build lifecycle — Design

**Date:** 2026-06-23
**Status:** approved (brainstormed + grilled against CONTEXT.md / ADR-0003); see ADR-0004
**Branch:** `feat/b1-image-lifecycle` off `dev` → merged **locally** (per ROADMAP: `dev` stays local)
**ROADMAP item:** §B foundation-completion, piece 1 of 3 (chosen first: smallest, independent, fully Mac-validatable).

## 1. Context

`ContainerService.build_image` exists but is reachable only through `just build-images`, whose
4-image list is hardcoded in the justfile and duplicates knowledge the package should own. Image
currency is therefore a manual step, and a **stale** image (one whose dockerfile or baked script
changed but was never rebuilt) silently breaks the pipeline — this was the exact root cause of the
earlier rootfs bug (`io/scripts/rootfs.sh` changed; the `like_rootfs` image was never rebuilt).

B1 makes image currency a package responsibility: one canonical image manifest, auto-build of
**missing** images on a run, and a content-hash **staleness warning** that would have caught the
rootfs bug. The other two §B pieces (x86_64-on-Mac in-container debuggee; un-gating bind/Linux)
are separate specs; B1 is independent of both.

## 2. Decisions (resolved during brainstorm)

- **Manifest home:** new `src/likedbg/images.py` owns the canonical manifest + orchestration; the
  justfile `build-images` recipe **delegates** to `start_kgdb --build-images` (one source of truth).
- **Missing image at run time:** **auto-build** with a log line (one-command ethos), then proceed.
- **Staleness:** stamp each image with a content-hash label `likedbg.input_sha`; on a run, compare
  the live image's label to the freshly-computed hash and **WARN** on mismatch (no mid-run rebuild).
- **Hash scope:** each image declares its **build inputs** explicitly (the dockerfile + any baked
  scripts); the hash is over those files' contents. A dockerfile-only hash would miss the rootfs
  bug (a changed baked script), so `build_inputs` covers `io/scripts/rootfs.sh` for the rootfs image.
- **Debuggee image deferred to B2** (its first consumer; not built today, unvalidated).
- **Required-image set is per run path:** the build-run ensures all of `IMAGES`; `--use`
  (launch-only) ensures only `(BASE, DEBUGGER)` — it boots a cached build and never needs
  kbuilder/rootfs.
- **`build_inputs` completeness is test-enforced:** a strict test parses each dockerfile's
  `COPY`/`ADD` and fails if a local source is missing from that image's `build_inputs` (and fails
  on unhandled patterns like globs/dirs, forcing a conscious update).
- **Glossary + ADR:** `Container image` added to `CONTEXT.md` (its Docker tag/label distinguished
  from the cache **Label**); the staleness approach is recorded as **ADR-0004**.

## 3. Component design

### 3.1 `src/likedbg/images.py` (new) — manifest + orchestration

```python
@dataclass(frozen=True)
class ImageSpec:
    tag: str                        # from constants (BASE_IMAGE, KBUILDER_IMAGE, ...)
    dockerfile: str                 # e.g. ".dockerfile_base"
    build_inputs: tuple[str, ...]   # workspace-relative files whose content defines the image;
                                    # build_inputs[0] is always the dockerfile
    buildargs: dict[str, str]       # {"USER": "user"}

# Dependency order: base first (the others are FROM like_dbg_base:latest).
IMAGES: tuple[ImageSpec, ...] = (
    ImageSpec(BASE_IMAGE,     ".dockerfile_base",     (".dockerfile_base",),                          {"USER": "user"}),
    ImageSpec(KBUILDER_IMAGE, ".dockerfile_kbuilder", (".dockerfile_kbuilder",),                      {"USER": "user"}),
    ImageSpec(ROOTFS_IMAGE,   ".dockerfile_rootfs",   (".dockerfile_rootfs", "io/scripts/rootfs.sh"), {"USER": "user"}),
    ImageSpec(DEBUGGER_IMAGE, ".dockerfile_dbg",      (".dockerfile_dbg",),                            {"USER": "user"}),
)
# NOTE: the debuggee image (.dockerfile_dbge, FROM base) is added here in B2 (x86_64-on-Mac),
# its first consumer. It is intentionally absent now (unbuilt + unvalidated today).

_LABEL = "likedbg.input_sha"

def input_sha(spec: ImageSpec, workspace: Path) -> str:
    """sha256 over the sorted (relpath, content) of the spec's build inputs."""
    h = hashlib.sha256()
    for rel in sorted(spec.build_inputs):
        h.update(rel.encode()); h.update(b"\0")
        h.update((workspace / rel).read_bytes()); h.update(b"\0")
    return h.hexdigest()

def build_images(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> None:
    """(Re)build every spec in order, stamping the input_sha label."""
    for s in specs:
        logger.info(f"building image {s.tag} from {s.dockerfile}")
        container.build_image(s.dockerfile, s.tag, s.buildargs, labels={_LABEL: input_sha(s, workspace)})

def ensure_current(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> list[str]:
    """Auto-build MISSING images (in order); return the tags of present-but-STALE images.
    The caller warns about stale tags — ensure_current does not rebuild them."""
    stale: list[str] = []
    for s in specs:
        want = input_sha(s, workspace)
        if not container.image_exists(s.tag):
            logger.info(f"building missing image {s.tag} from {s.dockerfile}")
            container.build_image(s.dockerfile, s.tag, s.buildargs, labels={_LABEL: want})
        elif container.image_labels(s.tag).get(_LABEL) != want:
            stale.append(s.tag)
    return stale
```
`images.py` imports `constants` (tags) + `ContainerService` (type) + `hashlib`/`logger` — no cycle.

### 3.2 `ContainerService` extension

- `build_image(self, dockerfile, tag, buildargs, *, nocache=False, labels=None)` — pass `labels`
  through to `self._client.images.build(..., labels=labels)`. Existing callers (none pass `labels`)
  are unaffected (`labels=None` → docker-py default).
- New `image_labels(self, tag) -> dict[str, str]` — `self._client.images.get(tag).labels or {}`;
  raises `ContainerError` (consistent with `image_exists`) only if the lookup itself errors — but
  `ensure_current` calls it solely after `image_exists` is True, so the image is present.

### 3.3 `cli.py` wiring

- New `--build-images` flag (action="store_true"). Dispatched **early**, Docker-only (after the
  docker client is created, before the tmux check — alongside `--clean`/`--list` style): calls
  `images.build_images(container, workspace)` and returns 0. This is the canonical refresh.
- On the **default run path** and the **`--use` path**, after the docker client is created and
  (build-run) after `require_volume_mode`, but **before `session.start`** (so missing-image build
  logs and the stale WARN print in the base pane before `open_debug_layout` splits it), call
  `stale = images.ensure_current(container, workspace, specs=<required set>)`: it auto-builds
  missing required images and returns the stale tags. For each stale tag,
  `logger.warning(f"image {tag} looks stale (build inputs changed); run \`start_kgdb --build-images\` to refresh")`.
  The run proceeds.
- **Required set per path:** the build-run passes all of `IMAGES` (base/kbuilder/rootfs/debugger —
  all four are touched by build+boot+debug). `--use` passes `(BASE, DEBUGGER)` only — `DEBUGGER`
  for gdb, `BASE` for the rare re-export when the host `Image` was deleted (`export.py` short-circuits
  otherwise); it never builds a kernel or rootfs.

### 3.4 `justfile`

```make
build-images:
    uv run ./start_kgdb --build-images
```
(keep the explanatory comment). Removes the hardcoded 4-image list; the package manifest is now
the single source of truth.

## 4. Testing strategy

TDD per unit; tests in `./tests/`.

- **`input_sha` (`tests/test_images.py`):** deterministic for fixed inputs; changes when any
  build-input file's content changes (write two temp dockerfiles/scripts, assert different hashes;
  edit the baked script, assert the hash moves — the rootfs-bug case); stable when unchanged.
- **`IMAGES` manifest sanity:** base is first; every spec's `build_inputs[0] == spec.dockerfile`;
  rootfs's inputs include `io/scripts/rootfs.sh`; tags equal the `constants` values; debuggee absent.
- **`build_inputs` completeness (the staleness guard's guard):** for each `ImageSpec`, parse its
  dockerfile's `COPY`/`ADD` directives, collect local source paths (exclude URLs and `--from=`
  stage copies), and assert each is present in `build_inputs`. **Strict:** an unhandled pattern
  (glob/dir) fails the test, forcing a conscious update of both the test and `build_inputs`. Today
  this asserts exactly that `io/scripts/rootfs.sh` is declared for the rootfs image.
- **`build_images` / `ensure_current`:** fake `ContainerService` recording `build_image` calls and
  faking `image_exists`/`image_labels`. Assert: `build_images` calls in dependency order with the
  `input_sha` label; `ensure_current` builds a missing image, returns `[]` when all present+current,
  returns the tag when a label mismatches, and does **not** rebuild the stale one.
- **`ContainerService.build_image` labels + `image_labels`:** fake docker client asserts `labels`
  is forwarded to `images.build`, and `image_labels` returns the image's labels (defaulting `{}`).
- **`cli`:** `--build-images` builds all `IMAGES` in order without requiring tmux (Docker-only
  dispatch); the run path and `--use` path call `ensure_current` before constructing the pipeline.
- **Gate:** `uv run ruff check src tests`, `uv run ruff format --check src tests`,
  `uv run mypy src/likedbg`, `uv run pytest -q` all green.

## 5. Live-gate verification (M5)

1. `uv run ./start_kgdb --build-images` builds all four images cleanly and stamps `likedbg.input_sha`
   (`docker inspect like_rootfs:latest --format '{{ index .Config.Labels "likedbg.input_sha" }}'`).
2. Touch a build input (e.g. append a comment to `io/scripts/rootfs.sh`), run `uv run ./start_kgdb`,
   and confirm the **stale WARN** fires for `like_rootfs:latest` and the run still proceeds.
3. Remove an image (`docker rmi like_debugger:latest`), run `uv run ./start_kgdb`, and confirm it is
   **auto-built** with a log line before the pipeline.

## 6. Non-goals

- **Debuggee image** (`.dockerfile_dbge`) — added to `IMAGES` in B2 (its first consumer).
- **Auto-rebuild on stale** — we WARN, never rebuild mid-run (no surprise multi-minute builds).
- **Upstream drift** — gef/pwndbg cloned in `.dockerfile_dbg`, the `ubuntu:26.04` base — not
  tracked; only local build-input *content* is hashed.
- **Runtime COPY auto-parsing** — at run time `build_inputs` is the explicit, hashed list, not
  parsed from the dockerfile (avoids glob/dir/`.dockerignore` fragility). A **test-time**
  completeness check (§4) *does* parse `COPY`/`ADD` to enforce that `build_inputs` covers every
  baked local file, so a future `COPY` lacking a `build_inputs` entry fails CI (mirrors
  ADR-0003 / ADR-0004's declared-input discipline).
- **`nocache` rebuilds** — `--build-images` uses normal layer-cached builds (Docker rebuilds changed
  layers); `nocache` stays an unused `build_image` parameter.
