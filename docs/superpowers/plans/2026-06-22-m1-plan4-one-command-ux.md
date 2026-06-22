# M1 Plan 4 — One-Command UX (assembly + tmux session + real debugger image) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing `likedbg` stages into a single command that builds → boots (native HVF) → attaches gdb for arm64, laid out in a tmux session, with a real GEF debugger image — turning the validated pieces into a `start_kgdb`-style daily driver.

**Architecture:** A new `assembly` composes `HostProfile` (with docker-context-resolved client) + the full `Pipeline` (Download→Unpack→Build→Rootfs→Export→Debuggee→Debugger) and injects launch closures that drive native QEMU (Mac host) and the gdb container into dedicated tmux panes via the `Session`. Command construction is pure/testable; the live one-command run is the empirical gate. Honors the Plan 2/3 bring-up findings (colima socket, `host.docker.internal` `--add-host`, `hbreak`, volume artifact export).

**Tech Stack:** Python 3.12, Pydantic, docker-py, tmux, `qemu-system-aarch64 -accel hvf`, `gdb-multiarch`+GEF; uv/ruff/mypy.

## Global Constraints

- Branching: `main` untouched. Feature branch `feat/m1-cli` off `dev`, merged after review. Live one-command validation on `feat/m1-live-cli`.
- Package boundary: new code under `src/likedbg/`; tests under `tests/`; legacy flat `src/*.py` untouched (ruff `force-exclude`). `mypy --strict` clean over `src/likedbg`; `ruff check .`/`ruff format --check .` clean; line length 120. Run tools with `uv run`.
- Errors use `LikeDbgError` subclasses with `remedy=`; side-effects behind injected seams.
- Bring-up facts to honor (validated live, see `docs/superpowers/notes/2026-06-22-arm64-boot-bringup.md`): native QEMU runs on the Mac host (a tmux pane); the gdb container needs `--add-host=host.docker.internal:host-gateway` and mounts `likedbg_ksrc` ro at `/ksrc`; the initial `start_kernel` break must be `hbreak`; the docker client is built from the active context (colima) via `docker_env`.

---

### Task 1: Real GEF debugger image

Modernize `.dockerfile_dbg` for Ubuntu 24.04 with `gdb-multiarch` + GEF (the minimal image proved the plumbing; this is the real UX). BRING-UP: build + confirm GEF loads.

**Files:**
- Modify: `.dockerfile_dbg`

**Interfaces:** Produces a `like_debugger:latest` image with `gdb-multiarch` and GEF auto-loaded from `~/.gdbinit`.

- [ ] **Step 1: Rewrite `.dockerfile_dbg`**

```dockerfile
FROM like_dbg_base:latest
LABEL maintainer="Christopher Krah <admin@0x434b.dev>"
ENV DEBIAN_FRONTEND=noninteractive
ARG USER=user

RUN apt-get update && apt-get install -yq --no-install-recommends \
        gdb-multiarch python3 python3-pip wget ca-certificates procps && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# GEF: single-file, robust, kernel-friendly.
RUN wget -q -O /root/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py && \
    echo "source /root/.gdbinit-gef.py" > /root/.gdbinit

WORKDIR /io
```

- [ ] **Step 2: Build and verify GEF loads**

Run:
```bash
docker build -f .dockerfile_dbg -t like_debugger:latest --build-arg USER=user .
docker run --rm like_debugger:latest gdb-multiarch -q -batch -ex "gef" 2>&1 | grep -iE "gef|GDB Enhanced" | head -2
```
Expected: GEF banner / `gef` command recognized. If the single-file fetch fails, record the fix (e.g. pin a release URL). No unit test (image build).

- [ ] **Step 3: Commit**

```bash
git add .dockerfile_dbg
git commit -m "feat: modern GEF debugger image (.dockerfile_dbg, Ubuntu 24.04)"
```

---

### Task 2: Launch-command builders

Pure functions that build the native-QEMU pane command and the gdb-container pane command from the context — testable, no side effects.

**Files:**
- Create: `src/likedbg/launchers.py`
- Create: `tests/test_launchers.py`

**Interfaces:**
- Consumes: nothing (operates on the argv lists the Debuggee/Debugger stages already build and pass to their `launch`/`run_gdb` callables).
- Produces:
  - `qemu_pane_command(argv: list[str]) -> str` — joins the QEMU argv for a host shell pane.
  - `gdb_pane_command(gdb_args: list[str], *, image: str, kernel_volume: str) -> str` — wraps the gdb argv in `docker run --rm -it --add-host=host.docker.internal:host-gateway -v <kernel_volume>:/ksrc:ro <image> <gdb args>`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_launchers.py`:

```python
from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_pane_command


def test_qemu_pane_command_joins_argv():
    cmd = qemu_pane_command(["qemu-system-aarch64", "-accel", "hvf", "-kernel", "/ws/Image"])
    assert cmd == "qemu-system-aarch64 -accel hvf -kernel /ws/Image"


def test_gdb_pane_command_wraps_docker_run_with_addhost_and_volume():
    cmd = gdb_pane_command(
        ["gdb-multiarch", "-q", "/ksrc/linux-6.6.30/vmlinux", "-ex", "hbreak start_kernel"],
        image="like_debugger:latest", kernel_volume="likedbg_ksrc",
    )
    assert cmd.startswith("docker run --rm")
    assert "--add-host=host.docker.internal:host-gateway" in cmd
    assert "-v likedbg_ksrc:/ksrc:ro" in cmd
    assert "like_debugger:latest" in cmd
    assert "hbreak start_kernel" in cmd
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_launchers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.launchers'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/launchers.py`:

```python
"""Wrap the stage-built argv into the shell commands that run in tmux panes: native
QEMU on the host, gdb inside the debugger container. Pure string construction — the
Debuggee/Debugger stages build the argv from the live context and pass it here; the
Session sends the result to a tmux pane."""

from __future__ import annotations


def qemu_pane_command(argv: list[str]) -> str:
    return " ".join(argv)


def gdb_pane_command(gdb_args: list[str], *, image: str, kernel_volume: str) -> str:
    docker = (
        f"docker run --rm -it --add-host=host.docker.internal:host-gateway "
        f"-v {kernel_volume}:/ksrc:ro {image} "
    )
    return docker + " ".join(gdb_args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_launchers.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/launchers.py tests/test_launchers.py
git commit -m "feat: launch-command builders (native QEMU pane + gdb container pane)"
```

---

### Task 3: tmux session layout

Extend `Session` with the 3-pane debugging layout (control + debuggee + debugger) used by the assembly.

**Files:**
- Modify: `src/likedbg/session.py`
- Modify: `tests/test_session.py`

**Interfaces:**
- Produces (added to `Session`):
  - `start(name: str) -> None` — rename the current session/window to `name`.
  - `open_debug_layout() -> tuple[int, int]` — split into 3 panes, returning `(debuggee_pane, debugger_pane)` indices. Concretely: from pane 0, `splitw -h -p 66`, `splitw -v -p 50`, leaving pane 0 = control, returns `(1, 2)`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_session.py`)

```python
def test_open_debug_layout_splits_into_three_panes():
    rec = Recorder()
    debuggee, debugger = Session("LIKE-DBG", runner=rec).open_debug_layout()
    assert (debuggee, debugger) == (1, 2)
    joined = [" ".join(c) for c in rec.calls]
    assert any("splitw" in c for c in joined)
    assert sum("splitw" in c for c in joined) == 2  # two splits -> three panes
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_session.py::test_open_debug_layout_splits_into_three_panes -v`
Expected: FAIL with `AttributeError: 'Session' object has no attribute 'open_debug_layout'`.

- [ ] **Step 3: Add the methods to `src/likedbg/session.py`** (inside the `Session` class)

```python
    def start(self, name: str) -> None:
        self._tmux("rename-session", name)
        self._tmux("rename-window", name)

    def open_debug_layout(self) -> tuple[int, int]:
        self.select_pane(0)
        self.split("h", 66)
        self.split("v", 50)
        self.select_pane(0)
        return (1, 2)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_session.py -v && uv run mypy src/likedbg`
Expected: all pass; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/session.py tests/test_session.py
git commit -m "feat: tmux 3-pane debug layout on Session"
```

---

### Task 4: CLI assembly

Compose the whole run: resolve the docker client (colima context), build `HostProfile`, assemble the `Pipeline` with all stages and the launch closures wired to tmux panes, and run. Provide a `start_kgdb` entrypoint. Assembly is testable with injected fakes (no real Docker/QEMU/tmux).

**Files:**
- Create: `src/likedbg/cli.py`
- Create: `start_kgdb` (executable Python entrypoint at repo root)
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `docker_env.resolve_docker_host`/`make_client`, `config.load_settings`, `HostProfile.detect`, `ContainerService`, `Session`, all stages, `launchers`.
- Produces:
  - `build_pipeline(container, session, *, workspace, kernel_volume, dl_dir, debugger_image, ext, panes) -> Pipeline` — composes Download, Unpack, Build, Rootfs, ArtifactExporter, DebuggeeStage(launch=…), DebuggerStage(ext, run_gdb=…, breakpoint="start_kernel"); the `launch`/`run_gdb` closures `session.send_keys` the `launchers` commands to the given panes.
  - `main(argv: list[str] | None = None) -> int` — parse args (`--config`, `-v`), require `$TMUX`, load settings, resolve+make docker client, detect `HostProfile`, `session.start("LIKE-DBG")`, `open_debug_layout()`, run the pipeline; typed-error → message+exit-code.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.cli import build_pipeline
from likedbg.container_service import ContainerService
from likedbg.session import Session


def test_build_pipeline_includes_all_stage_names():
    sent: list[str] = []
    session = Session("X", runner=lambda a: 0)
    object.__setattr__(session, "send_keys", lambda cmd: sent.append(cmd))  # capture
    pipe = build_pipeline(
        ContainerService(SimpleNamespace()), session,
        workspace=Path("/ws"), kernel_volume="likedbg_ksrc", dl_dir=Path("/ws/kernels"),
        debugger_image="like_debugger:latest", ext="gef", panes=(1, 2),
    )
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert names == ["download", "unpack", "build", "rootfs", "export", "debuggee", "debugger"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.cli'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/cli.py`:

```python
"""Top-level assembly: compose the pipeline + launchers + tmux session into one command."""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request
from pathlib import Path

from loguru import logger

from likedbg import docker_env
from likedbg.config import load_settings
from likedbg.container_service import ContainerService
from likedbg.errors import LikeDbgError
from likedbg.host_profile import HostProfile
from likedbg.launchers import gdb_pane_command
from likedbg.launchers import qemu_pane_command
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext
from likedbg.session import Session
from likedbg.stages.build import BuildStage
from likedbg.stages.debuggee import DebuggeeStage
from likedbg.stages.debugger import DebuggerStage
from likedbg.stages.download import DownloadStage
from likedbg.stages.export import ArtifactExporter
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.unpack import UnpackStage

_FRAGMENTS = ["configs/fragments/debug.config", "configs/fragments/no-kaslr.config", "configs/fragments/generic.config"]


def _fetch(url: str, dest: Path) -> None:
    urllib.request.urlretrieve(url, str(dest))  # noqa: S310


def build_pipeline(
    container: ContainerService,
    session: Session,
    *,
    workspace: Path,
    kernel_volume: str,
    dl_dir: Path,
    debugger_image: str,
    ext: str,
    panes: tuple[int, int],
) -> Pipeline:
    debuggee_pane, debugger_pane = panes

    def launch_qemu(argv: list[str]) -> None:
        session.select_pane(debuggee_pane)
        session.send_keys(qemu_pane_command(argv))

    def run_gdb(args: list[str]) -> None:
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(args, image=debugger_image, kernel_volume=kernel_volume))

    return Pipeline([
        DownloadStage(_fetch, dl_dir=dl_dir),
        UnpackStage(container, kernel_volume=kernel_volume, workspace=workspace),
        BuildStage(container, kbuilder_image="like_kbuilder_arm64:latest", fragments=_FRAGMENTS,
                   workspace=workspace, kernel_volume=kernel_volume),
        RootfsStage(container, rootfs_image="like_rootfs:latest", workspace=workspace),
        ArtifactExporter(container, kernel_volume=kernel_volume, workspace=workspace),
        DebuggeeStage(launch=launch_qemu),
        DebuggerStage(ext=ext, run_gdb=run_gdb, breakpoint="start_kernel"),
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="start_kgdb")
    parser.add_argument("--config", "-c", default="")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    if not os.getenv("TMUX"):
        logger.error("Not running inside a TMUX session. Start tmux first.")
        return 2
    try:
        workspace = Path.cwd()
        settings = load_settings(
            workspace / "configs" / "system.ini", workspace / "configs" / "user.ini",
            custom_ini=Path(args.config) if args.config else None,
        )
        client = docker_env.make_client(docker_env.resolve_docker_host(env=os.environ))
        container = ContainerService(client)
        host = HostProfile.detect(settings, workspace)
        session = Session("LIKE-DBG")
        session.start("LIKE-DBG")
        panes = session.open_debug_layout()
        pipeline = build_pipeline(
            container, session, workspace=workspace, kernel_volume="likedbg_ksrc",
            dl_dir=workspace / "kernels", debugger_image="like_debugger:latest",
            ext=settings.debugger.ext, panes=panes,
        )
        ctx = PipelineContext(settings=settings, host=host)
        pipeline.run(ctx)
        return 0
    except LikeDbgError as exc:
        logger.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Create `start_kgdb` (repo root, executable):

```python
#!/usr/bin/env python3
import sys

from likedbg.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v && uv run mypy src/likedbg`
Expected: 1 passed; mypy clean. (Then `chmod +x start_kgdb`.)

- [ ] **Step 5: Commit**

```bash
chmod +x start_kgdb
git add src/likedbg/cli.py start_kgdb tests/test_cli.py
git commit -m "feat: one-command CLI assembly (pipeline + launchers + tmux session)"
```

---

### Task 5: Live one-command run (EMPIRICAL — run & observe)

> **Empirical gate.** Inside tmux, run `./start_kgdb` (arm64) and confirm it builds (or reuses), boots native HVF in the debuggee pane, and attaches GEF hitting `start_kernel` in the debugger pane — one command. Run on `feat/m1-live-cli`. Fold back any wiring fixes; record the transcript.

- [ ] **Step 1:** Ensure `configs/user.ini` sets `arch = arm64`. From inside `tmux`, run `./start_kgdb` (or `uv run ./start_kgdb`).
- [ ] **Step 2:** Confirm: pane 1 shows native QEMU booting under HVF; pane 2 shows GEF attached at the `start_kernel` breakpoint. Reuse of the existing build/rootfs/Image should make this fast.
- [ ] **Step 3:** Record the working one-command UX (and any closure/path fixes) in `docs/superpowers/notes/2026-06-22-one-command-ux.md`; fold fixes back (keeping unit tests green); commit.

---

## Self-Review

- **Spec coverage:** real GEF debugger image (Task 1); native-QEMU + gdb-container command builders honoring the bring-up findings — `--add-host`, volume mount, `hbreak`, gef-remote (Task 2); tmux 3-pane layout (Task 3); the CLI assembly wiring docker-context client + all stages + launchers + session, with a `start_kgdb` entrypoint (Task 4); the live one-command validation (Task 5). The one-command build→boot→debug UX from the spec's M1 goal.
- **Placeholder scan:** Tasks 1–4 carry complete code/commands; Task 5 is explicitly empirical.
- **Type consistency:** `build_pipeline`/`main` signatures, the stage constructors (matching Plan 1–3), `qemu_pane_command`/`gdb_pane_command`, and `Session.open_debug_layout` are consistent across tasks and tests. The launch closures simply wrap the argv the Debuggee/Debugger stages already build from the live context (no context injection) — `DebuggeeStage.run` builds the QEMU argv from `ctx.kernel_image` (host path, rewritten by Export) and `DebuggerStage.run` builds the gdb argv from `ctx.vmlinux` (the in-volume path the gdb container mounts), so the closures only need the argv passed to them.
