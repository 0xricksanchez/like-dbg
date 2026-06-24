# Logging & Session Ergonomics — Design

**Date:** 2026-06-24
**Status:** approved (brainstormed + grilled). **Implemented as TWO sequenced plans** off `dev` (merged
**locally**): **Plan 1 `feat/observability-logging`** (§3.1–3.3 + §3.6 pipeline timing) FIRST, then **Plan 2
`feat/process-panes`** (§3.4–3.5) off updated `dev`. Plan 2 adds **ADR-0005** (debug-pane process isolation).
**Motivation:** surfaced by the §B3 live-gate — a first-run rootfs failure was undiagnosable because
`RootfsStage` discards its container logs; plus the user wants a real logging system (stderr + file) and
the debug session's internal commands kept out of their shell history.

## 1. Context

Three observability/ergonomics gaps in the current runtime:

1. **Logging is unconfigured.** No `logger.add()`/`remove()`/`configure()` anywhere → loguru's default
   sink (everything to stderr, colorized). `--verbose/-v` is parsed in `cli.main` but **never wired** to
   anything — a dead flag. There is no persistent log file.
2. **Container output is invisible or discarded.** `ContainerService.exec` **blocks** (not streamed), so a
   10-minute `make all` shows nothing live; on success the output is dropped by callers, on failure it is
   embedded in the `ContainerError`. `RootfsStage` **streams but discards** (`for line in …: _ = line`) — so
   when the rootfs build fails, the `RootfsError` is generic ("did not produce the image") with no logs.
   This is exactly what made the B3 live-gate's first-run rootfs failure a mystery.
3. **The debug session pollutes shell history.** `start_kgdb` runs in the user's shell (so `uv run
   ./start_kgdb` is correctly in history), then `Session.open_debug_layout` `split-window`s **new shell
   panes** and the Debuggee/Debugger stages `send-keys` the `docker run … qemu …` / `… gdb …` commands
   **into those pane shells** — which write them to `~/.bash_history` / zsh history on exit. Arrow-up in the
   user's terminal then shows the internal commands, not just `uv run ./start_kgdb`.

**Scope (decided): one cohesive "observability & session ergonomics" design, shipped as two independent
plans.** Plan 1 (observability) = a logging system + container-output capture (fixes the rootfs
diagnosability) + a rootfs retry + per-stage timing. Plan 2 (session hygiene) = shell-history isolation via
process-panes. The two halves touch mostly different files and neither depends on the other, so Plan 1 lands
the urgent rootfs follow-up + logging first, then Plan 2 (off updated `dev`) does the Session refactor.

## 2. Decisions (resolved during brainstorm)

- **Dual-sink logging** (chosen over single-rotating-file and minimal-no-file), split into two calls:
  `configure_stderr(verbose)` (all `main()` paths) + `add_run_logfile(workspace)` (the run/`--use` paths
  ONLY — a `--list`/`--clean`/`--build-images`/`--adopt` writes no file). stderr = human-facing
  (`INFO` default, `DEBUG` with `-v`), format `HH:MM:SS LEVEL message` (drop module:function:line); file =
  `artifacts/logs/run-<UTC>.log` always `DEBUG`, full format (ts + `name:function:line` + every line) +
  a `latest.log` symlink, with explicit cross-run pruning (keep last ~20). `artifacts/` is gitignored.
- **Container output logs at `DEBUG`** → always in the file; on stderr only with `-v`. Default stderr stays
  stage-level `INFO`; live detail without `-v` is `tail -f artifacts/logs/latest.log`.
- **Per-stage completion + duration** logged in `pipeline.py` (today only stage *start* is logged): wrap each
  stage with `time.monotonic()` → `stage <name> done (<Hm Ss>)` at `INFO`, so a no-`-v` run is informative.
- **The rootfs fix is routing the streamed container logs to the logger** (not discarding), so failures carry
  the tail. Generalized: `ContainerService.exec` streams + logs every line (the kernel build is visible too),
  via the low-level exec API created with **`tty=True`** so the stream is a single clean merged stream (no
  multiplex demux); the exit code comes from `exec_inspect`.
- **Rootfs retry: one retry on image-not-produced ONLY** (exceptions propagate immediately — don't mask a
  broken environment), with a `WARN` on the first miss. Works because attempt 1's `rootfs.sh` resets+re-registers
  the host binfmt as a side effect, so attempt 2 runs against a healed binfmt — exactly the B3 transient.
- **Shell-history isolation via process-panes** (chosen over `HISTFILE=/dev/null` env and `send_keys`+inline
  history-off): the qemu/gdb command **is** the pane's process (`split-window -d … '<cmd>'`), no interactive
  shell → no history at all, immune to the user's dotfiles. `-d` keeps focus on the user's base pane (today's
  end-state); `Session.send_keys`/`open_debug_layout` are **removed**.
- **`remain-on-exit on`** for the debug panes (stay visible after qemu/gdb quit, for inspection).
- **ADR-0005 (with Plan 2):** the process-panes/history-isolation decision is recorded — non-obvious vs the
  obvious `send-keys`, a real trade-off (no post-exit shell). Plan 1 needs no ADR. No new CONTEXT.md terms
  (run log / debug panes are implementation artifacts, not domain concepts).

## 3. Component design

### 3.1 `src/likedbg/logsetup.py` (new) — `configure_stderr` + `add_run_logfile`
(Named `logsetup`, **not** `logging`, to avoid shadowing the stdlib `logging` module.)
Two calls so trivial subcommands write no file:
```python
def configure_stderr(*, verbose: bool) -> None:
    """Remove loguru's default sink; add the human-facing stderr sink. Called at the top of cli.main
    for ALL paths. Wires the previously-dead --verbose."""
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "INFO",
               format="<green>{time:HH:mm:ss}</green> <level>{level: <5}</level> {message}", colorize=True)

def add_run_logfile(workspace: Path) -> Path:
    """Add the full-detail per-run file sink. Called ONLY on the run / --use paths. Returns the run-log path."""
    logs = workspace / "artifacts" / "logs"            # artifacts/ is gitignored
    logs.mkdir(parents=True, exist_ok=True)
    _prune_old_logs(logs, keep=20)
    run_log = logs / f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.log"
    logger.add(run_log, level="DEBUG",
               format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <7} | {name}:{function}:{line} - {message}")
    _point_latest(logs / "latest.log", run_log)        # best-effort symlink; swallow OSError
    return run_log
```
- stderr format drops `name:function:line` (kept only in the file). `-v` flips stderr to `DEBUG` (shows the
  streamed container lines live); the file is always `DEBUG`.
- `_prune_old_logs(logs, keep)` removes all but the newest `keep` `run-*.log` (sorted by name — the UTC
  timestamp sorts chronologically). Explicit, **not** loguru `retention` (each run is a separate process with
  a new filename — no in-process rotation for loguru to prune across).
- `cli.main`: `configure_stderr(verbose=args.verbose)` right after parsing args (all paths); the run-launching
  branches (default run, `--use`) then call `add_run_logfile(workspace)`. `--list`/`--clean`/`--build-images`/
  `--adopt` get stderr only. New module imports: `sys`, `datetime`/`UTC`, `Path`, loguru `logger`.

### 3.2 `ContainerService.exec` — stream + log (`src/likedbg/container_service.py`)
Replace the blocking `container.exec_run` with the low-level streaming API so output is live, captured, and
the exit code is still authoritative:
```python
def exec(self, container, cmd, *, workdir=None) -> ExecResult:
    api = self._client.api
    # tty=True => a single clean merged stream (no 8-byte stdout/stderr multiplex frames to demux).
    exec_id = api.exec_create(container.id, ["/bin/sh", "-c", cmd], workdir=workdir, tty=True)["Id"]
    chunks: list[str] = []
    for chunk in api.exec_start(exec_id, tty=True, stream=True):
        text = chunk.decode(errors="replace") if isinstance(chunk, bytes) else str(chunk)
        chunks.append(text)
        for line in text.splitlines():
            logger.debug(line)            # DEBUG: always to the file, stderr only with -v
    output = "".join(chunks)
    exit_code = api.exec_inspect(exec_id)["ExitCode"]
    if exit_code != 0:
        raise ContainerError(f"command failed (exit {exit_code}): {cmd}\n{_tail(output)}",
                             remedy="inspect the command output above / artifacts/logs/latest.log")
    return ExecResult(exit_code=exit_code, output=output)
```
- **`tty=True`** on both `exec_create` and `exec_start` merges stdout+stderr into one raw stream (the stage
  containers already run `tty=True`); without it `exec_start(stream=True)` yields multiplexed frames with
  binary headers. `_tail(output, n=40)` trims the embedded error to the last N lines (full output is in the file).
- All `exec` callers (Build/Unpack/Export/adopt/cache-removal) get live-streamed, logged output for free; no
  caller changes. The test fakes override `exec` directly, so stage tests are unaffected; `test_container_service`
  gets a fake `client.api` (`exec_create`/`exec_start`/`exec_inspect`).

### 3.3 `RootfsStage` — route logs + retry (`src/likedbg/stages/rootfs.py`)
- Replace `for line in container.logs(stream=True, follow=True): _ = line` with
  `logger.debug(line.decode(errors="replace").rstrip())` — **the diagnosability fix**.
- Extract the single attempt (start container → stream logs → stop → return `target.exists()`) into a helper
  `_attempt(ctx) -> bool`. `run()` calls it; **exceptions propagate immediately** (a docker/setup error is
  not retried — don't mask a broken environment). Only on `not ok` (container ran but produced no image) does
  it `logger.warning("rootfs build did not produce the image; retrying once …")` and call `_attempt` once
  more; if the retry is also `not ok`, raise `RootfsError` (message references `artifacts/logs/latest.log`,
  which now holds the container tail).
- Rationale for why one retry suffices: attempt 1's `rootfs.sh` resets+re-registers the host binfmt as a side
  effect, so attempt 2 runs against a healed binfmt — exactly the B3 first-run transient. Rootfs-only;
  build/unpack are not retried.

### 3.4 `Session` — process-panes (`src/likedbg/session.py`)
- Add:
  ```python
  def run_in_new_pane(self, *, target: int | str, direction: Literal["h","v"], percent: int, cmd: str) -> str:
      pane = self._query(["tmux", "split-window", "-d", "-P", "-F", "#{pane_id}",
                          f"-{direction}", "-p", str(percent), "-t", str(target), cmd])
      self._tmux("set-option", "-p", "-t", pane, "remain-on-exit", "on")
      return pane                      # the new pane's stable %id
  ```
  The `cmd` becomes the pane's process (tmux runs it via a non-interactive shell, not an interactive one) →
  **no history**. `-d` keeps focus on the user's base pane (matching today's `select_pane(base)` end-state).
  `-P -F '#{pane_id}'` returns the new pane's stable id so the debugger splits from the debuggee's pane
  deterministically (no reliance on the active pane). `cmd` is one argv element — the existing `shlex`-joined
  command string (from `launchers.py`) reaches tmux's shell intact, same parsing as the old `send-keys` path.
- **Remove `open_debug_layout` and `send_keys`** (their only users were the debug closures). `select_pane`/
  `split` become unused too — drop them (and the `test_session` cases). `kill()`/`pane_base_index()`/`start()` stay.
- The base pane remains the user's shell (`uv run ./start_kgdb` is the only thing in its history).

### 3.5 Stages + CLI wiring (`stages/debuggee.py`, `stages/debugger.py`, `cli.py`)
- `DebuggeeStage`'s injected callable changes from `send: Callable[[str], None]` (send into a pre-made pane)
  to `launch: Callable[[str], None]` (create the qemu pane with the command). `DebuggerStage.run_gdb` likewise
  launches the gdb pane. The stage bodies are otherwise unchanged (they still build the argv → command string).
- `cli.build_pipeline`/`build_use_pipeline` no longer take `panes`/call `open_debug_layout`. They take the
  `session` + the base pane id and build the two launch closures with explicit targets:
  ```python
  base = session.pane_base_index()
  qemu_pane: dict[str, str] = {}
  def launch_debuggee(cmd): qemu_pane["id"] = session.run_in_new_pane(target=base, direction="h", percent=66, cmd=cmd)
  def launch_debugger(cmd): session.run_in_new_pane(target=qemu_pane["id"], direction="v", percent=50, cmd=cmd)
  ```
  Geometry is identical to today (left = user shell + pipeline log; right-top = qemu; right-bottom = gdb), but
  built on demand by the stages and never via an interactive shell. `cli.main`/`cmd_use` drop the
  `panes = session.open_debug_layout()` call.

### 3.6 Per-stage timing (`src/likedbg/pipeline.py`) — Plan 1
The runner wraps each stage with `time.monotonic()` and logs completion + duration (today it logs only
`running stage: {name}` at the start):
```python
for stage in self._stages:
    if stage.should_skip(ctx): logger.debug(f"skipping stage: {stage.name}"); continue
    logger.info(f"stage {stage.name}: started")
    t0 = time.monotonic()
    ctx = stage.run(ctx)
    logger.info(f"stage {stage.name}: done ({_fmt_duration(time.monotonic() - t0)})")
```
`_fmt_duration(seconds)` → `"3m40s"` / `"12s"`. `time` is a stdlib import. This is the no-`-v` progress signal.

### 3.7 Plan boundary
**Plan 1 (`feat/observability-logging`):** §3.1 `logsetup.py`, §3.2 `ContainerService.exec` streaming, §3.3
`RootfsStage` log-routing + retry, §3.6 `pipeline.py` timing, and the `cli.main` logging calls
(`configure_stderr` + `add_run_logfile`). No Session/pane changes — `cli` still uses today's
`open_debug_layout`+`send_keys`. **Plan 2 (`feat/process-panes`, off updated `dev`):** §3.4 `Session`, §3.5
stage/cli pane wiring, + **ADR-0005**. `cli.py` is touched by both, but in different regions (logging calls vs
pane wiring), and Plan 2 branches off Plan-1-merged `dev`, so no collision.

## 4. Regression safety

The logging and streaming changes are additive (no behavioral change to builds/boots); the QEMU/gdb **command
strings** (`launchers.py`, `qemu.py`, `gdbcmd.py`) are byte-identical — only command *delivery* changes
(`run_in_new_pane` vs `open_debug_layout`+`send_keys`). macOS volume (native-HVF) and Linux bind both work
unchanged. The full suite stays green; new behavior is covered by new tests. `ContainerService.exec`'s public
contract (returns `ExecResult`, raises `ContainerError` with output on non-zero) is preserved.

## 5. Testing strategy

Unit (in `./tests/`). **Plan 1:**
- `configure_stderr`/`add_run_logfile` (inspect `logger` sinks via a fake or `logger.remove` accounting):
  `configure_stderr` removes the default + adds one stderr sink at `INFO`/`DEBUG` per `verbose`;
  `add_run_logfile(tmp_path)` creates `artifacts/logs/run-*.log` + `latest.log`, returns the path, and prunes
  to the newest 20 (seed 22, assert 20 remain).
- `ContainerService.exec` (fake `client.api` with `exec_create`/`exec_start`/`exec_inspect`): `tty=True` is
  passed; streamed chunks → each line logged at DEBUG; returns `ExecResult(joined output, inspected exit)`;
  non-zero exit → `ContainerError` with command + output tail. (`test_container_service` updated to the fake api.)
- `RootfsStage`: streamed lines are logged (not discarded); image-not-produced on attempt 1 → one `WARN` +
  second attempt; second success → image recorded + manifest written; second miss → `RootfsError` with tail; an
  **exception** in `_attempt` propagates (NOT retried). Volume/bind both still write the host image (unchanged).
- `pipeline.py`: each non-skipped stage logs `stage <name>: started` and `stage <name>: done (<dur>)`;
  `_fmt_duration` formats `3m40s`/`12s`. (Inject a fake clock or assert the message shape.)

**Plan 2:**
- `Session.run_in_new_pane`: emits `split-window -d -P -F #{pane_id} -<dir> -p <pct> -t <target> '<cmd>'` (fake
  runner/query), sets `remain-on-exit on`, returns the queried pane id. `Session` no longer has `send_keys`/
  `open_debug_layout`/`select_pane`/`split` (those tests removed).
- `DebuggeeStage`/`DebuggerStage` (fake `launch`): the launch callable receives the expected qemu/gdb command
  (in-container vs native-host for debuggee; gef/pwndbg for debugger) — same assertions as today, via `launch`.
- `cli.build_pipeline`/`build_use_pipeline`: stage-name lists unchanged; constructed with `session`/base (no
  `panes`); `open_debug_layout` no longer referenced; the debuggee/debugger closures call `run_in_new_pane`.
- Gate (each plan): `uv run ruff check src tests`, `ruff format --check`, `uv run mypy src/likedbg`,
  `uv run pytest -q` green.

## 6. Live verification (arm64 Ubuntu 26.04 VM)

Use the warm VM (see memory `reference-linux-live-gate-vm`). **Plan 1 gate:** a normal `uv run ./start_kgdb`
run — build/rootfs/boot detail lands in `artifacts/logs/run-<UTC>.log` (+ `latest.log`); stderr shows
stage-level INFO with completion+duration (and `-v` shows the streamed make/debootstrap lines); a `--list`
writes **no** log file; force an image-not-produced rootfs failure and confirm `RootfsError` + `latest.log`
carry the container tail and the single retry fires; both arches still build→boot→gdb→userspace.
**Plan 2 gate:** after a run + detach, the host shell's history (arrow-up / `history`) shows only
`uv run ./start_kgdb` — no `docker run`/qemu/gdb commands; the 3-pane geometry is unchanged; both arches
still build→boot→gdb→userspace (no regression from the delivery change).

## 7. Non-goals

- **Structured/JSON logging, remote log shipping, log levels per-module:** out of scope; plain stderr + file.
- **Streaming the QEMU/gdb pane output into the logger:** those are interactive panes the user watches
  directly; only the *build/rootfs* container output is logged.
- **Retry for build/unpack/export:** only rootfs (the one observed transient); no speculative general retry.
- **A post-exit shell in the debug panes:** process-panes intentionally have no shell; `remain-on-exit`
  keeps the pane visible. (If a re-run shell is later wanted, that's a separate enhancement.)
- **Changing the QEMU/gdb commands or the tmux geometry:** unchanged.
