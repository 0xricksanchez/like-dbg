# B1 — Image-build lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** make container-image currency a package responsibility — a canonical image manifest, `--build-images` to (re)build all, auto-build of missing images on a run, and a content-hash staleness WARN (ADR-0004) that catches a changed dockerfile *or baked script*.

**Architecture:** A new `src/likedbg/images.py` owns the `IMAGES` manifest (tag→dockerfile→`build_inputs`→buildargs), a content hash (`input_sha`) over each image's declared build inputs, and two orchestrators (`build_images`, `ensure_current`). `ContainerService` gains a `labels` arg on `build_image` plus `image_labels`. `cli.py` adds a Docker-only `--build-images` dispatch and calls `ensure_current` (subset per path) before the tmux session starts. The justfile delegates to the package.

**Tech Stack:** Python 3.12, docker-py, loguru, pytest, mypy `--strict`, ruff, `uv` runner.

## Global Constraints

- Run everything via `uv run`. Type-check with **`uv run mypy src/likedbg`** — NOT `uv run mypy src` (that overrides the config scope and trips the quarantined legacy `src/debuggee.py`).
- `uv run ruff check src tests` and `uv run ruff format src tests` clean before each commit.
- TDD: failing test → run-it-fail → minimal impl → run-it-pass → commit. (Task 2's manifest-sanity and Task 4's parser-coverage tests are characterization tests that may pass on first write — that's fine; they pin contracts.)
- Full suite stays green (baseline at branch start: 139 tests; this plan adds tests, never removes).
- Branch `feat/b1-image-lifecycle` off `dev`; commit locally, **never `git push`**.
- The working tree has unrelated in-flight user edits (`.dockerfile_*`, `configs/user.ini`, `ctf/misc/cpio.sh`, `CODE_OF_CONDUCT.md`) — **never `git add -A`**; stage only the exact files each step names.
- The staleness docker label is exactly `likedbg.input_sha` (constant `images.LABEL`).
- The stale WARN message is exactly: `image {tag} looks stale (build inputs changed); run \`start_kgdb --build-images\` to refresh`.
- `IMAGES` order is dependency order (base first). Every spec's `build_inputs[0]` is its dockerfile.
- The debuggee image (`.dockerfile_dbge`) is **out of scope** (added in B2). See spec §6, ADR-0004.

---

### Task 1: `ContainerService` — `labels` on `build_image` + `image_labels`

**Files:**
- Modify: `src/likedbg/container_service.py` (`build_image`; new `image_labels`)
- Test: `tests/test_container_service.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `build_image(self, dockerfile, tag, buildargs, *, nocache=False, labels: dict[str,str] | None = None) -> None`; `image_labels(self, tag: str) -> dict[str, str]`.

- [ ] **Step 1: Extend the test fakes + write failing tests**

In `tests/test_container_service.py`, replace the `FakeImages` and `FakeClient` classes with versions that record build kwargs and carry labels (keep `FakeContainers` as-is):

```python
class FakeImages:
    def __init__(self, existing=(), labels=None):
        self._existing = set(existing)
        self._labels = labels or {}
        self.build_kwargs = None

    def get(self, tag):
        if tag in self._existing:
            return SimpleNamespace(tags=[tag], labels=self._labels.get(tag, {}))
        raise docker.errors.ImageNotFound(tag)

    def build(self, **kwargs):
        self.build_kwargs = kwargs
        return SimpleNamespace(id="built"), iter([])


class FakeClient:
    def __init__(self, existing=(), labels=None):
        self.images = FakeImages(set(existing), labels)
        self.containers = FakeContainers()
```

Then append these tests:

```python
def test_build_image_forwards_labels_and_args():
    client = FakeClient()
    svc = ContainerService(client)
    svc.build_image(".dockerfile_base", "like_dbg_base:latest", {"USER": "user"}, labels={"likedbg.input_sha": "abc"})
    kw = client.images.build_kwargs
    assert kw["dockerfile"] == ".dockerfile_base"
    assert kw["tag"] == "like_dbg_base:latest"
    assert kw["buildargs"] == {"USER": "user"}
    assert kw["labels"] == {"likedbg.input_sha": "abc"}


def test_image_labels_returns_image_labels():
    svc = ContainerService(FakeClient(existing=["t:latest"], labels={"t:latest": {"likedbg.input_sha": "xyz"}}))
    assert svc.image_labels("t:latest") == {"likedbg.input_sha": "xyz"}


def test_image_labels_missing_image_raises():
    svc = ContainerService(FakeClient())
    with pytest.raises(ContainerError):
        svc.image_labels("nope:latest")
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_container_service.py -k "labels" -v`
Expected: FAIL — `build_image` does not pass `labels` (and there is no `image_labels` attribute / it isn't defined yet → AttributeError or wrong build_kwargs).

- [ ] **Step 3: Implement**

In `src/likedbg/container_service.py`, change `build_image` and add `image_labels`:

```python
    def build_image(
        self,
        dockerfile: str,
        tag: str,
        buildargs: dict[str, str],
        *,
        nocache: bool = False,
        labels: dict[str, str] | None = None,
    ) -> None:
        try:
            self._client.images.build(
                path=".", dockerfile=dockerfile, tag=tag, buildargs=buildargs, nocache=nocache, rm=True, labels=labels
            )
        except docker.errors.APIError as exc:
            raise ContainerError(
                f"failed to build image {tag} from {dockerfile}: {exc}",
                remedy="check the Dockerfile and that the container runtime is running",
            ) from exc

    def image_labels(self, tag: str) -> dict[str, str]:
        try:
            image = self._client.images.get(tag)
        except docker.errors.ImageNotFound as exc:
            raise ContainerError(f"image not found: {tag}", remedy="build it first (`start_kgdb --build-images`)") from exc
        return image.labels or {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_container_service.py -v`
Expected: PASS (all, including the existing `test_run_detached_*`, `test_image_exists_*`, and the three new ones).

- [ ] **Step 5: Gate + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; suite green.

```bash
git add src/likedbg/container_service.py tests/test_container_service.py
git commit -m "feat(container): build_image labels + image_labels accessor"
```

---

### Task 2: `images.py` — manifest, `input_sha`, `copy_sources`

**Files:**
- Create: `src/likedbg/images.py`
- Test: `tests/test_images.py`

**Interfaces:**
- Consumes: `constants` (image tags).
- Produces: `ImageSpec(tag, dockerfile, build_inputs, buildargs)`; `IMAGES: tuple[ImageSpec, ...]`; `USE_IMAGES: tuple[ImageSpec, ...]`; `LABEL = "likedbg.input_sha"`; `input_sha(spec, workspace: Path) -> str`; `copy_sources(dockerfile_text: str) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_images.py`:

```python
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
    assert h1 == images.input_sha(spec, tmp_path)          # deterministic
    (tmp_path / "b").write_text("BETA")
    assert images.input_sha(spec, tmp_path) != h1          # an input's content changed
    (tmp_path / "b").write_text("beta")
    assert images.input_sha(spec, tmp_path) == h1          # restored


def test_input_sha_ignores_files_not_in_build_inputs(tmp_path):
    (tmp_path / "a").write_text("alpha")
    (tmp_path / "b").write_text("beta")
    spec = ImageSpec("t:latest", "a", ("a",), {"USER": "user"})   # only "a" is an input
    h1 = images.input_sha(spec, tmp_path)
    (tmp_path / "b").write_text("changed")
    assert images.input_sha(spec, tmp_path) == h1


def test_images_manifest_shape():
    assert images.IMAGES[0].tag == BASE_IMAGE                      # base first (dependency order)
    assert {s.tag for s in images.IMAGES} == {BASE_IMAGE, KBUILDER_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE}
    for s in images.IMAGES:
        assert s.build_inputs[0] == s.dockerfile                  # dockerfile is always input[0]
        assert s.buildargs == {"USER": "user"}
    rootfs = next(s for s in images.IMAGES if s.tag == ROOTFS_IMAGE)
    assert "io/scripts/rootfs.sh" in rootfs.build_inputs          # the baked script (prior-bug file)
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_images.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'likedbg.images'`.

- [ ] **Step 3: Create `src/likedbg/images.py`**

```python
"""Container-image manifest + content-hash currency (ADR-0004; CONTEXT.md -> Container image).

Each Container image is checked for staleness by a content hash (`input_sha`) over its declared
build inputs — the dockerfile plus any local files it bakes in via COPY/ADD — stamped onto the
built image as the docker label `likedbg.input_sha`. `build_inputs` is declared explicitly per
image; a test (tests/test_images.py::test_build_inputs_cover_every_copy_source) enforces that the
declaration covers every COPY/ADD source, so it cannot silently drift.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import ROOTFS_IMAGE

LABEL = "likedbg.input_sha"


@dataclass(frozen=True)
class ImageSpec:
    tag: str
    dockerfile: str
    build_inputs: tuple[str, ...]  # workspace-relative; build_inputs[0] is the dockerfile
    buildargs: dict[str, str]


# Dependency order: base first (the others are FROM like_dbg_base:latest).
IMAGES: tuple[ImageSpec, ...] = (
    ImageSpec(BASE_IMAGE, ".dockerfile_base", (".dockerfile_base",), {"USER": "user"}),
    ImageSpec(KBUILDER_IMAGE, ".dockerfile_kbuilder", (".dockerfile_kbuilder",), {"USER": "user"}),
    ImageSpec(ROOTFS_IMAGE, ".dockerfile_rootfs", (".dockerfile_rootfs", "io/scripts/rootfs.sh"), {"USER": "user"}),
    ImageSpec(DEBUGGER_IMAGE, ".dockerfile_dbg", (".dockerfile_dbg",), {"USER": "user"}),
)
# NOTE: the debuggee image (.dockerfile_dbge, FROM base) joins this manifest in B2 (x86_64-on-Mac),
# its first consumer; intentionally absent now (unbuilt + unvalidated today).

# `--use` is launch-only (boots a cached build): it needs gdb's debugger image, and base only for
# the rare re-export when the host Image was deleted. It never builds a kernel or rootfs.
USE_IMAGES: tuple[ImageSpec, ...] = tuple(s for s in IMAGES if s.tag in (BASE_IMAGE, DEBUGGER_IMAGE))


def input_sha(spec: ImageSpec, workspace: Path) -> str:
    """sha256 over the sorted (relpath, content) of the spec's build inputs."""
    h = hashlib.sha256()
    for rel in sorted(spec.build_inputs):
        h.update(rel.encode())
        h.update(b"\0")
        h.update((workspace / rel).read_bytes())
        h.update(b"\0")
    return h.hexdigest()


_COPY_RE = re.compile(r"^\s*(?:COPY|ADD)\s+(.*)$")
_GLOB_CHARS = set("*?[")


def copy_sources(dockerfile_text: str) -> list[str]:
    """Local source paths a dockerfile bakes in via COPY/ADD (for the build_inputs completeness test).

    Strict: raises ValueError on patterns we cannot statically resolve (globs, directory copies, the
    JSON-array form) so a future dockerfile change forces a conscious build_inputs update (ADR-0004).
    Skips URL sources and `--from=` multi-stage copies (not local build inputs).
    """
    out: list[str] = []
    for line in dockerfile_text.splitlines():
        m = _COPY_RE.match(line)
        if not m:
            continue
        rest = m.group(1).strip()
        if "--from" in rest:
            continue  # multi-stage copy: sources live in another build stage, not the workspace
        if rest.startswith("["):
            raise ValueError(f"unhandled JSON-array COPY/ADD form: {line!r}")
        tokens = [t for t in rest.split() if not t.startswith("--")]  # drop flags (e.g. --chown=)
        if len(tokens) < 2:
            raise ValueError(f"unparseable COPY/ADD (need source + dest): {line!r}")
        for src in tokens[:-1]:  # last token is the destination
            if src.startswith(("http://", "https://")):
                continue
            if src.endswith("/") or any(c in _GLOB_CHARS for c in src):
                raise ValueError(f"unhandled glob/dir COPY/ADD source {src!r} in: {line!r}")
            out.append(src)
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_images.py -v`
Expected: PASS (all 8 tests, including `test_build_inputs_cover_every_copy_source` against the real dockerfiles).

- [ ] **Step 5: Gate + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; suite green.

```bash
git add src/likedbg/images.py tests/test_images.py
git commit -m "feat(images): manifest + input_sha + COPY-completeness parser"
```

---

### Task 3: `images.py` — `build_images` + `ensure_current`

**Files:**
- Modify: `src/likedbg/images.py` (append orchestration + a loguru import)
- Test: `tests/test_images.py` (append)

**Interfaces:**
- Consumes: `ContainerService.build_image(..., labels=…)` + `image_exists` + `image_labels` (Task 1); `ImageSpec`, `IMAGES`, `input_sha`, `LABEL` (Task 2).
- Produces: `build_images(container, workspace, specs=IMAGES) -> None`; `ensure_current(container, workspace, specs=IMAGES) -> list[str]` (returns stale tags; auto-builds missing).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_images.py`:

```python
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
    assert stale == ["img_a:latest"]   # a is stale, b is current
    assert c.builds == []              # stale images are NOT rebuilt (warn-only, ADR-0004)


def test_ensure_current_honors_specs_subset(tmp_path):
    specs = _two_specs(tmp_path)
    c = _FakeContainer()
    images.ensure_current(c, tmp_path, (specs[0],))
    assert [tag for _, tag, _ in c.builds] == ["img_a:latest"]  # only the passed spec touched
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_images.py -k "build_images or ensure_current" -v`
Expected: FAIL — `AttributeError: module 'likedbg.images' has no attribute 'build_images'`.

- [ ] **Step 3: Implement**

Add the loguru import to `src/likedbg/images.py` (with the other imports) and append the two functions at the end of the module:

```python
from loguru import logger  # add alongside the existing imports

from likedbg.container_service import ContainerService  # add alongside the existing imports
```

```python
def build_images(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> None:
    """(Re)build every spec in dependency order, stamping the input_sha label."""
    for s in specs:
        logger.info(f"building image {s.tag} from {s.dockerfile}")
        container.build_image(s.dockerfile, s.tag, s.buildargs, labels={LABEL: input_sha(s, workspace)})


def ensure_current(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> list[str]:
    """Auto-build MISSING images (in order); return the tags of present-but-STALE images.

    Stale = the live image's `likedbg.input_sha` label != the freshly computed input_sha. The caller
    warns about stale tags; ensure_current never rebuilds them (warn-only, ADR-0004).
    """
    stale: list[str] = []
    for s in specs:
        want = input_sha(s, workspace)
        if not container.image_exists(s.tag):
            logger.info(f"building missing image {s.tag} from {s.dockerfile}")
            container.build_image(s.dockerfile, s.tag, s.buildargs, labels={LABEL: want})
        elif container.image_labels(s.tag).get(LABEL) != want:
            stale.append(s.tag)
    return stale
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_images.py -v`
Expected: PASS (all Task 2 + Task 3 tests).

- [ ] **Step 5: Gate + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; suite green.

```bash
git add src/likedbg/images.py tests/test_images.py
git commit -m "feat(images): build_images + ensure_current (auto-build missing, flag stale)"
```

---

### Task 4: `cli.py` `--build-images` + `ensure_current` wiring + justfile

**Files:**
- Modify: `src/likedbg/cli.py` (import `images`; `--build-images` arg + dispatch; `_ensure_images` helper; calls on the run + `--use` paths)
- Modify: `justfile` (`build-images` delegates to the package)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `images.build_images`, `images.ensure_current`, `images.IMAGES`, `images.USE_IMAGES` (Tasks 2-3).
- Produces: CLI flag `--build-images`; module-level `cli._ensure_images(container, workspace, *, specs) -> None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py` (the file already imports `SimpleNamespace`, `pytest`, `Settings`):

```python
def test_main_build_images_is_docker_only_and_invokes_build_images(monkeypatch):
    import likedbg.cli as cli

    built = []
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.images, "build_images", lambda container, workspace, *a, **k: built.append(True))
    monkeypatch.delenv("TMUX", raising=False)  # build-images must NOT require tmux

    assert cli.main(["--build-images"]) == 0
    assert built == [True]


def test_ensure_images_helper_warns_each_stale_tag(monkeypatch):
    import likedbg.cli as cli

    monkeypatch.setattr(cli.images, "ensure_current", lambda container, workspace, specs: ["like_rootfs:latest"])
    msgs = []
    monkeypatch.setattr(cli.logger, "warning", lambda msg: msgs.append(msg))
    cli._ensure_images(object(), object(), specs=())
    assert len(msgs) == 1
    assert "like_rootfs:latest" in msgs[0]
    assert "--build-images" in msgs[0]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_cli.py -k "build_images or ensure_images" -v`
Expected: FAIL — `cli` has no `images` attribute / no `--build-images` flag / no `_ensure_images` (AttributeError or argparse error).

- [ ] **Step 3: Implement — import + helper**

In `src/likedbg/cli.py`, add the import (with the other `from likedbg import …` imports):

```python
from likedbg import images
```

Add the helper near the other module-level helpers (e.g. after `require_volume_mode`):

```python
def _ensure_images(container: ContainerService, workspace: Path, *, specs: tuple[images.ImageSpec, ...]) -> None:
    for tag in images.ensure_current(container, workspace, specs):
        logger.warning(f"image {tag} looks stale (build inputs changed); run `start_kgdb --build-images` to refresh")
```

- [ ] **Step 4: Implement — argparse flag + dispatch + run-path wiring**

In `main()`, add the flag alongside the others:

```python
    parser.add_argument("--build-images", action="store_true")
```

Add the Docker-only dispatch immediately after `container = ContainerService(client)` (before the `--clean` block):

```python
        container = ContainerService(client)
        if args.build_images:
            images.build_images(container, workspace)
            return 0
```

On the **default run path**, insert the ensure call after `require_volume_mode(host)` and before `session = Session("LIKE-DBG")`:

```python
        host = HostProfile.detect(settings, workspace)
        require_volume_mode(host)
        _ensure_images(container, workspace, specs=images.IMAGES)
        session = Session("LIKE-DBG")
```

On the **`--use` path**, insert the ensure call after the TMUX check and before `session = Session("LIKE-DBG")`:

```python
        if args.use:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            _ensure_images(container, workspace, specs=images.USE_IMAGES)
            session = Session("LIKE-DBG")
            session.start("LIKE-DBG")
            panes = session.open_debug_layout()
            return cmd_use(...)   # unchanged args
```

(Leave the `cmd_use(...)` call arguments exactly as they are.)

- [ ] **Step 5: Run tests to verify pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS (the two new tests + all existing cli tests).

- [ ] **Step 6: Update the justfile**

In `justfile`, replace the four `docker build …` lines under `build-images:` with the delegation (keep the explanatory comment block above the recipe):

```make
build-images:
    uv run ./start_kgdb --build-images
```

- [ ] **Step 7: Gate + commit**

Run: `uv run ruff check src tests && uv run ruff format src tests && uv run mypy src/likedbg && uv run pytest -q`
Expected: clean; full suite green.

```bash
git add src/likedbg/cli.py tests/test_cli.py justfile
git commit -m "feat(cli): --build-images + auto-build/stale-warn on run paths; justfile delegates"
```

---

## Final verification (whole branch)

- [ ] **Full gate:** `uv run ruff format --check src tests && uv run ruff check src tests && uv run mypy src/likedbg && uv run pytest -q` — all green.
- [ ] **Spec coverage:** §3.1 images.py (Tasks 2-3); §3.2 ContainerService (Task 1); §3.3 cli wiring incl. subset-per-path + pre-session placement (Task 4); §3.4 justfile (Task 4); §4 tests incl. completeness guard (Task 2). ADR-0004 + glossary already committed.
- [ ] **Live gate (M5), per spec §5:**
  1. `uv run ./start_kgdb --build-images` builds all 4 cleanly; `docker inspect like_rootfs:latest --format '{{ index .Config.Labels "likedbg.input_sha" }}'` shows a hash.
  2. Append a comment to `io/scripts/rootfs.sh`, run `uv run ./start_kgdb`, confirm the stale WARN fires for `like_rootfs:latest` and the run proceeds.
  3. `docker rmi like_debugger:latest`, run `uv run ./start_kgdb`, confirm it auto-builds with a log line before the panes split.
- [ ] **Finish:** `superpowers:finishing-a-development-branch` → merge `feat/b1-image-lifecycle` into `dev` **locally**; update ROADMAP §B (B1 done) + project memory.

## Self-Review

- **Spec coverage:** every spec section maps to a task (see Final-verification checklist). The `Container image` glossary term and ADR-0004 were committed during the grill.
- **Placeholder scan:** no TBD/TODO; every code step shows complete code + exact commands. The one `cmd_use(...)` ellipsis is explicitly annotated "leave args unchanged" (the call already exists in the file).
- **Type consistency:** `build_image(..., labels=None)`, `image_labels(tag)->dict`, `input_sha(spec, workspace)->str`, `copy_sources(text)->list[str]`, `build_images(...)->None`, `ensure_current(...)->list[str]`, `_ensure_images(..., *, specs)` are referenced consistently across Tasks 1-4; `LABEL`/`IMAGES`/`USE_IMAGES` names match between `images.py` and `cli.py`.
