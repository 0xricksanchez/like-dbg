# Observability & Logging (Plan 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give like-dbg a real logging system (human stderr + a full-detail per-run file), make container build/rootfs output live + captured (fixing the rootfs diagnosability gap from the B3 live-gate) with a one-shot rootfs retry, and log per-stage timing.

**Architecture:** A new `logsetup.py` configures loguru's two sinks (`configure_stderr` for all CLI paths, `add_run_logfile` for run/`--use` only). `ContainerService.exec` switches to the low-level streaming docker API (`tty=True`) so every line is logged at DEBUG and captured for the error tail. `RootfsStage` routes its streamed container logs to the logger and retries once on image-not-produced. `pipeline.py` logs each stage's completion + duration.

**Tech Stack:** Python 3.12 (uv), loguru (already a dep), docker-py low-level `client.api`, pytest. This is **Plan 1 of 2** from the spec; Plan 2 (process-panes) is separate and lands after.

## Global Constraints

- **`dev` stays local — never `git push`.** This work lands on branch `feat/observability-logging` off `dev`, merged **locally**.
- **No new runtime dependencies** (loguru is already used).
- **`ContainerService.exec`'s public contract is preserved:** returns `ExecResult(exit_code, output)`, raises `ContainerError` with the command + output tail on non-zero exit.
- **The new module is `src/likedbg/logsetup.py`, NOT `logging.py`** (avoid shadowing stdlib `logging`).
- **macOS (volume/native-HVF) and Linux (bind) both keep working** — these changes are additive/observability; no build/boot behavior change.
- **Loguru is a global singleton:** any test that reconfigures it (`configure_stderr`) or adds a capture sink MUST restore loguru state afterward (a fixture that snapshots/removes handlers), so it doesn't leak into other tests.
- **Per-task gate (before each commit):** `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q` — all green.
- **Spec:** `docs/superpowers/specs/2026-06-24-logging-session-ergonomics-design.md` (§3.1–3.3, §3.6, §3.7 Plan-1 boundary).

---

### Task 1: `logsetup.py` — stderr + per-run file sinks

**Files:**
- Create: `src/likedbg/logsetup.py`
- Test: `tests/test_logsetup.py`

**Interfaces:**
- Produces: `configure_stderr(*, verbose: bool) -> None`; `add_run_logfile(workspace: Path) -> Path`;
  `_prune_old_logs(logs: Path, *, keep: int) -> None`; `_point_latest(link: Path, target: Path) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_logsetup.py`:
```python
from pathlib import Path

import pytest
from loguru import logger

from likedbg import logsetup


@pytest.fixture(autouse=True)
def _restore_logger():
    # logsetup mutates the global loguru logger; snapshot handler ids and restore after each test.
    before = set(logger._core.handlers)  # noqa: SLF001
    yield
    for hid in set(logger._core.handlers) - before:  # noqa: SLF001
        logger.remove(hid)


def test_configure_stderr_sets_level_by_verbose():
    logsetup.configure_stderr(verbose=False)
    levels = [h.levelno for h in logger._core.handlers.values()]  # noqa: SLF001
    assert 20 in levels  # INFO
    logsetup.configure_stderr(verbose=True)
    levels = [h.levelno for h in logger._core.handlers.values()]  # noqa: SLF001
    assert 10 in levels  # DEBUG


def test_add_run_logfile_creates_file_latest_and_captures_debug(tmp_path):
    run_log = logsetup.add_run_logfile(tmp_path)
    assert run_log.parent == tmp_path / "artifacts" / "logs"
    assert run_log.name.startswith("run-") and run_log.suffix == ".log"
    logger.debug("hello-marker")
    logger.complete()
    assert "hello-marker" in run_log.read_text()
    latest = tmp_path / "artifacts" / "logs" / "latest.log"
    assert latest.is_symlink() and latest.resolve() == run_log.resolve()


def test_prune_old_logs_keeps_newest(tmp_path):
    logs = tmp_path / "artifacts" / "logs"
    logs.mkdir(parents=True)
    for i in range(22):
        (logs / f"run-20260624T0000{i:02d}Z.log").write_text("x")
    logsetup._prune_old_logs(logs, keep=20)  # noqa: SLF001
    remaining = sorted(p.name for p in logs.glob("run-*.log"))
    assert len(remaining) == 20
    assert remaining[0] == "run-20260624T000002Z.log"  # the 2 oldest pruned
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_logsetup.py -q`
Expected: FAIL (`likedbg.logsetup` does not exist).

- [ ] **Step 3: Implement**

Create `src/likedbg/logsetup.py`:
```python
"""loguru sink configuration: a human-facing stderr sink (all CLI paths) and a full-detail
per-run file (run / --use paths only). Named `logsetup`, not `logging`, to avoid shadowing
the stdlib module."""

from __future__ import annotations

import sys
from datetime import UTC
from datetime import datetime
from pathlib import Path

from loguru import logger

_STDERR_FMT = "<green>{time:HH:mm:ss}</green> <level>{level: <5}</level> {message}"
_FILE_FMT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <7} | {name}:{function}:{line} - {message}"


def configure_stderr(*, verbose: bool) -> None:
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "INFO", format=_STDERR_FMT, colorize=True)


def _prune_old_logs(logs: Path, *, keep: int) -> None:
    existing = sorted(logs.glob("run-*.log"))  # UTC-timestamp names sort chronologically
    for old in existing[: max(0, len(existing) - keep)]:
        old.unlink(missing_ok=True)


def _point_latest(link: Path, target: Path) -> None:
    try:
        link.unlink(missing_ok=True)
        link.symlink_to(target.name)  # relative — same dir
    except OSError:
        pass  # symlinks unavailable (e.g. Windows) — non-fatal


def add_run_logfile(workspace: Path) -> Path:
    logs = workspace / "artifacts" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    _prune_old_logs(logs, keep=20)
    run_log = logs / f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.log"
    logger.add(run_log, level="DEBUG", format=_FILE_FMT)
    _point_latest(logs / "latest.log", run_log)
    return run_log
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_logsetup.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/logsetup.py tests/test_logsetup.py
git commit -m "feat(logsetup): stderr + per-run file loguru sinks"
```

---

### Task 2: `ContainerService.exec` — streaming + DEBUG logging

**Files:**
- Modify: `src/likedbg/container_service.py` (`exec`)
- Test: `tests/test_container_service.py` (replace the 3 `exec` tests)

**Interfaces:**
- Consumes: nothing new (uses `self._client.api` + loguru `logger`).
- Produces: `exec(container, cmd, *, workdir=None) -> ExecResult` — unchanged signature/contract, now streams + logs each line at DEBUG via the low-level docker API with `tty=True`.

- [ ] **Step 1: Replace the 3 exec tests with streaming-fake versions**

In `tests/test_container_service.py`, add a fake api + replace `test_exec_returns_result_on_success`, `test_exec_raises_on_nonzero`, `test_exec_wraps_command_in_shell` with:
```python
class FakeApi:
    def __init__(self, chunks=(b"ok\n",), exit_code=0):
        self.chunks, self.exit_code = chunks, exit_code
        self.created = None
        self.start_kwargs = None

    def exec_create(self, container, cmd, workdir=None, tty=False):
        self.created = {"container": container, "cmd": cmd, "workdir": workdir, "tty": tty}
        return {"Id": "e1"}

    def exec_start(self, exec_id, tty=False, stream=False):
        self.start_kwargs = {"tty": tty, "stream": stream}
        return iter(self.chunks)

    def exec_inspect(self, exec_id):
        return {"ExitCode": self.exit_code}


def _svc_with_api(chunks=(b"ok\n",), exit_code=0):
    client = FakeClient()
    client.api = FakeApi(chunks, exit_code)
    return ContainerService(client), client.api


def test_exec_streams_returns_result_and_logs(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="DEBUG", format="{message}")
    try:
        svc, api = _svc_with_api(chunks=[b"line1\n", b"line2\n"], exit_code=0)
        res = svc.exec(SimpleNamespace(id="c1"), "true", workdir="/io")
        logger.complete()
    finally:
        logger.remove(sink)
    assert res.exit_code == 0
    assert res.output == "line1\nline2\n"
    assert api.created["cmd"] == ["/bin/sh", "-c", "true"] and api.created["workdir"] == "/io"
    assert api.created["tty"] is True and api.start_kwargs["tty"] is True
    assert any("line1" in m for m in msgs) and any("line2" in m for m in msgs)


def test_exec_raises_on_nonzero_with_tail():
    svc, _ = _svc_with_api(chunks=[b"boom\n"], exit_code=2)
    with pytest.raises(ContainerError) as exc:
        svc.exec(SimpleNamespace(id="c1"), "false")
    assert "boom" in str(exc.value)
```
Add the imports at the top of the file: `from loguru import logger` (and `SimpleNamespace` is already imported).

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_container_service.py -q`
Expected: FAIL (`exec` still calls `container.exec_run`, ignores `client.api`; old tests deleted).

- [ ] **Step 3: Implement**

In `src/likedbg/container_service.py`, add `from loguru import logger` at the top, and a tail helper + the new `exec`:
```python
def _tail(text: str, n: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:])


# in class ContainerService:
    def exec(self, container: Any, cmd: str, *, workdir: str | None = None) -> ExecResult:
        # Stream via the low-level API with tty=True so output is a single clean merged stream
        # (no stdout/stderr multiplex frames) and every line is logged live at DEBUG.
        api = self._client.api
        exec_id = api.exec_create(container.id, ["/bin/sh", "-c", cmd], workdir=workdir, tty=True)["Id"]
        chunks: list[str] = []
        for chunk in api.exec_start(exec_id, tty=True, stream=True):
            text = chunk.decode(errors="replace") if isinstance(chunk, bytes) else str(chunk)
            chunks.append(text)
            for line in text.splitlines():
                logger.debug(line)
        output = "".join(chunks)
        exit_code = api.exec_inspect(exec_id)["ExitCode"]
        if exit_code != 0:
            raise ContainerError(
                f"command failed (exit {exit_code}): {cmd}\n{_tail(output)}",
                remedy="inspect the output above / artifacts/logs/latest.log",
            )
        return ExecResult(exit_code=exit_code, output=output)
```

- [ ] **Step 4: Run to verify they pass (whole suite — fakes that override `exec` are unaffected)**

Run: `uv run pytest tests/test_container_service.py -q && uv run pytest -q`
Expected: PASS. (Stage tests subclass `ContainerService` and override `exec`, so they don't hit the new code.)

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/container_service.py tests/test_container_service.py
git commit -m "feat(container): streaming exec (tty=True) with live DEBUG logging"
```

---

### Task 3: `RootfsStage` — route container logs + retry once

**Files:**
- Modify: `src/likedbg/stages/rootfs.py` (route `container.logs` to the logger; extract `_attempt`; retry on image-not-produced)
- Test: `tests/test_stage_rootfs.py`

**Interfaces:**
- Consumes: loguru `logger`.
- Produces: `RootfsStage.run` retries the build **once** when the image is not produced; logs the streamed container output at DEBUG; raises `RootfsError` (referencing `artifacts/logs/latest.log`) only after the retry also fails. Exceptions are NOT retried.

- [ ] **Step 1: Write the failing tests**

In `tests/test_stage_rootfs.py`, add `from loguru import logger` and append:
```python
def test_rootfs_routes_container_logs_to_logger(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="DEBUG", format="{message}")
    try:
        c = FakeC()
        ctx = _ctx(tmp_path)
        rootfs_target(tmp_path, _rrecipe().label).parent.mkdir(parents=True, exist_ok=True)
        rootfs_target(tmp_path, _rrecipe().label).write_bytes(b"img")
        RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert any("building" in m for m in msgs)  # FakeC.logs yields b"building\n"


class _RetryFakeC(FakeC):
    """Produces the image only on the SECOND build attempt (simulates the first-run transient)."""

    def __init__(self, target: Path):
        super().__init__()
        self._target = target
        self.attempts = 0

    def run_detached(self, image, **kwargs):
        self.attempts += 1
        if self.attempts == 2:
            self._target.parent.mkdir(parents=True, exist_ok=True)
            self._target.write_bytes(b"img")
        return super().run_detached(image, **kwargs)


def test_rootfs_retries_once_on_missing_image_then_succeeds(tmp_path):
    msgs = []
    sink = logger.add(msgs.append, level="WARNING", format="{message}")
    try:
        target = rootfs_target(tmp_path, _rrecipe().label)
        c = _RetryFakeC(target)
        ctx = _ctx(tmp_path)
        out = RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert c.attempts == 2 and out.rootfs_image == target
    assert any("retry" in m.lower() for m in msgs)


def test_rootfs_exception_is_not_retried(tmp_path):
    class _BoomC(FakeC):
        def run_detached(self, image, **kwargs):
            raise RuntimeError("docker down")

    c = _BoomC()
    ctx = _ctx(tmp_path)
    with pytest.raises(RootfsError):  # run_detached failure is wrapped, propagates without retry
        RootfsStage(c, recipe=_rrecipe(), rootfs_image="like_rootfs", workspace=tmp_path).run(ctx)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_stage_rootfs.py -q`
Expected: FAIL (logs discarded → no "building"; no retry → `attempts` stays 1; the retry test's image never appears).

- [ ] **Step 3: Implement**

In `src/likedbg/stages/rootfs.py`, add `from loguru import logger`. Replace the build body of `run()` (from `target.parent.mkdir(...)` through the `if not target.exists(): raise RootfsError(...)`) so the attempt is a helper and `run()` retries once on miss:
```python
    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.rootfs_label is None:
            raise RootfsError("no rootfs label in context", remedy="the CLI must set ctx.rootfs_label")
        label = ctx.rootfs_label
        target = rootfs_target(self._workspace, label)

        if cache.manifest_exists(self._workspace, "rootfs", label):
            m = cache.load_manifest(self._workspace, "rootfs", label)
            img = Path(m.paths["image_host"])
            if not img.exists():
                raise CacheError(
                    f"cached rootfs {label} image is gone",
                    remedy=f"`start_kgdb --clean {label}` and rebuild",
                )
            ctx.rootfs_image = img
            return ctx

        if not self._attempt(target):
            logger.warning("rootfs build did not produce the image; retrying once...")
            if not self._attempt(target):
                raise RootfsError(
                    f"rootfs build did not produce {target}",
                    remedy="see artifacts/logs/latest.log (rootfs.sh output); the container exited without writing the image",
                )
        ctx.rootfs_image = target
        cache.write_manifest(
            self._workspace,
            cache.Manifest(
                kind="rootfs",
                label=label,
                key=self._recipe.key,
                version="",
                arch=self._recipe.arch,
                storage_mode=ctx.host.storage_mode,
                inputs=self._recipe.cache_inputs(),
                paths={"image_host": str(target)},
            ),
        )
        return ctx

    def _attempt(self, target: Path) -> bool:
        target.parent.mkdir(parents=True, exist_ok=True)
        qemu_arch = "aarch64" if self._recipe.arch == "arm64" else "x86_64"
        cmd = (
            f"/bin/bash -lc '. /home/user/rootfs.sh -n {target.name} -a {qemu_arch} "
            f"-d {self._recipe.distribution} -u user -h {self._recipe.hostname}'"
        )
        try:
            container = self._c.run_detached(
                self._image,
                volumes={str(target.parent): {"bind": _MOUNT, "mode": "rw"}},
                privileged=True,
                detach=True,
                command=cmd,
            )
        except Exception as exc:  # noqa: BLE001
            raise RootfsError("failed to start rootfs build container", remedy="check the rootfs image exists") from exc
        for line in container.logs(stream=True, follow=True):
            logger.debug(line.decode(errors="replace").rstrip() if isinstance(line, bytes) else str(line).rstrip())
        self._c.stop(container)
        return target.exists()
```
(`Path`, `cache`, `_MOUNT`, `RootfsError`, `CacheError` are already imported.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_stage_rootfs.py -q`
Expected: PASS — including the existing `test_rootfs_build_without_image_raises_and_writes_no_manifest` (now raises after two attempts) and the reuse/build tests.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/rootfs.py tests/test_stage_rootfs.py
git commit -m "feat(rootfs): route container logs to logger; retry once on image-not-produced"
```

---

### Task 4: `pipeline.py` — per-stage completion + duration

**Files:**
- Modify: `src/likedbg/pipeline.py` (`Pipeline.run` timing + `_fmt_duration`)
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Produces: each non-skipped stage logs `stage <name>: started` and `stage <name>: done (<dur>)` at INFO; `_fmt_duration(seconds: float) -> str`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_pipeline.py`, add `from loguru import logger` and `from likedbg.pipeline import _fmt_duration`, and append:
```python
def test_fmt_duration():
    assert _fmt_duration(12) == "12s"
    assert _fmt_duration(220) == "3m40s"


def test_logs_stage_start_and_done():
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        Pipeline([RecordStage("build")]).run(_ctx())
        logger.complete()
    finally:
        logger.remove(sink)
    joined = "\n".join(msgs)
    assert "stage build: started" in joined
    assert "stage build: done (" in joined
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -q`
Expected: FAIL (`_fmt_duration` undefined; the runner logs `running stage: build`, not `started`/`done`).

- [ ] **Step 3: Implement**

In `src/likedbg/pipeline.py`, add `import time` and `_fmt_duration`, and update `Pipeline.run`:
```python
import time


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60}m{s % 60}s" if s >= 60 else f"{s}s"


# in class Pipeline:
    def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self._stages:
            if stage.should_skip(ctx):
                logger.debug(f"skipping stage: {stage.name}")
                continue
            logger.info(f"stage {stage.name}: started")
            t0 = time.monotonic()
            ctx = stage.run(ctx)
            logger.info(f"stage {stage.name}: done ({_fmt_duration(time.monotonic() - t0)})")
        return ctx
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_pipeline.py -q`
Expected: PASS (incl. the existing order/skip/threading tests).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/pipeline.py tests/test_pipeline.py
git commit -m "feat(pipeline): log per-stage completion + duration"
```

---

### Task 5: CLI wiring — `configure_stderr` (all paths) + `add_run_logfile` (run/--use)

**Files:**
- Modify: `src/likedbg/cli.py` (call `configure_stderr` near the top of `main`; `add_run_logfile` in the run + `cmd_use` paths)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `logsetup.configure_stderr`, `logsetup.add_run_logfile` (Task 1).

- [ ] **Step 1: Write the failing test**

In `tests/test_cli.py`, append (mirrors the existing `test_main_build_images...` monkeypatch pattern):
```python
def test_main_configures_stderr_always_but_logfile_only_for_runs(monkeypatch):
    import likedbg.cli as cli

    calls = {"stderr": 0, "logfile": 0}
    monkeypatch.setattr(cli, "load_settings", lambda *a, **k: Settings())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda env: "unix:///x")
    monkeypatch.setattr(cli.docker_env, "make_client", lambda host: SimpleNamespace())
    monkeypatch.setattr(cli.logsetup, "configure_stderr", lambda **k: calls.__setitem__("stderr", calls["stderr"] + 1))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda ws: calls.__setitem__("logfile", calls["logfile"] + 1))
    monkeypatch.setattr(cli, "summarize_cache", lambda ws: ["(cache empty)"])

    assert cli.main(["--list"]) == 0
    assert calls["stderr"] == 1   # configure_stderr runs for every invocation
    assert calls["logfile"] == 0  # --list writes no run log file
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_main_configures_stderr_always_but_logfile_only_for_runs -q`
Expected: FAIL (`cli` has no `logsetup` attribute / `configure_stderr` never called).

- [ ] **Step 3: Implement**

In `src/likedbg/cli.py`:
- Add `from likedbg import logsetup` with the other imports.
- In `main`, immediately after `args = parser.parse_args(argv)`, add: `logsetup.configure_stderr(verbose=args.verbose)`.
- In the **default run** path (right after `host = HostProfile.detect(settings, workspace)` / before building the pipeline) add: `logsetup.add_run_logfile(workspace)`.
- In `cmd_use` (right after `host = HostProfile.detect(...)`) add: `logsetup.add_run_logfile(workspace)`.

(`--list`/`--clean`/`--build-images`/`--adopt` get no `add_run_logfile`.)

- [ ] **Step 4: Run the full suite green**

Run: `uv run pytest -q`
Then the gate: `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg`.
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): configure_stderr for all paths; add_run_logfile for run/--use"
```

---

## Live verification (controller-run, NOT a subagent task)

After merge, the controller runs Plan 1's gate on the arm64 VM (spec §6, Plan 1 gate): a normal `uv run ./start_kgdb` run lands build/rootfs/boot detail in `artifacts/logs/run-<UTC>.log` (+ `latest.log`); stderr shows `HH:MM:SS LEVEL` stage lines with `done (Ns)` durations (and `-v` shows the streamed make/debootstrap lines); a `--list` writes **no** log file; an image-not-produced rootfs failure surfaces the tail in `RootfsError` + `latest.log` and the single retry fires; both arches still build→boot→gdb→userspace.

## Self-review

- **Spec coverage:** §3.1 logsetup→T1; §3.2 streaming exec→T2; §3.3 rootfs route+retry→T3; §3.6 pipeline timing→T4; §3.7 cli logging wiring→T5. All Plan-1 spec sections have a task. (§3.4/§3.5 = Plan 2, excluded.)
- **Placeholder scan:** none — every step has full code/tests.
- **Type consistency:** `configure_stderr(*, verbose: bool)` / `add_run_logfile(workspace) -> Path` (T1, consumed T5); `exec(...) -> ExecResult` contract preserved (T2); `_attempt(target: Path) -> bool` (T3); `_fmt_duration(float) -> str` (T4). Names consistent across tasks. The streaming `exec` keeps the `ExecResult`/`ContainerError` contract the stage tests rely on (they override `exec`, so unaffected).
