# Process Panes & Debuggee Restart (Plan 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move QEMU/GDB delivery from `send-keys` into tmux shells to process panes that do not pollute shell history, then add the first debugging-session control: restart the Debuggee pane in place and manually reconnect GDB.

**Architecture:** `Session` becomes the only tmux driver for process panes and session state. Debuggee/Debugger stages still build the exact same command strings, but receive `launch` callbacks instead of shell `send` callbacks. CLI assembly creates process panes on demand, stores tmux session state (`@likedbg_*`), and adds `--restart-debuggee` as the stable control command. `gdbcmd.py` exposes a `likedbg-reconnect` helper for GEF/pwndbg. The checked-in `.tmux.conf` becomes a self-contained LIKE-DBG workflow config with `C-b B` bound to restart.

**Tech Stack:** Python 3.12 (uv), tmux, pytest, loguru, no new runtime deps.

## Global Constraints

- **Branching:** land this on `feat/process-panes` off updated local `dev` after Plan 1 is merged locally. Never `git push`.
- **Scope:** Plan 2 only. No logging/rootfs/container-streaming changes; those belong to Plan 1.
- **Command strings remain byte-equivalent.** `qemu.py`, `launchers.py`, and the Docker/QEMU command construction should not change except for GDB reconnect helper additions.
- **No shell-history pollution.** QEMU/GDB commands must be pane processes (`split-window ... <cmd>` / `respawn-pane ... <cmd>`), not text sent into interactive shells.
- **No runtime tmux key mutation.** The project `.tmux.conf` owns `C-b B`; application code does not call `bind-key`.
- **Process panes stay inspectable.** Debuggee/Debugger panes have pane-local `remain-on-exit on`; new panes set it
  inside the pane before `exec` to avoid a fast-exit race, and Debuggee restart reasserts it before respawn.
- **Restart is state-scoped.** Use current tmux session `@likedbg_*` options, not the session name.
- **Focus preservation:** restart never steals focus, including fallback recreate.
- **Per-task gate before commit:** `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q`.
- **Spec:** `docs/superpowers/specs/2026-06-24-logging-session-ergonomics-design.md` (§3.4–3.5 + Plan 2 decisions).

---

### Task 1: `Session` process-pane + tmux-state primitives

**Files:**
- Modify: `src/likedbg/session.py`
- Modify: `tests/test_session.py`

**Interfaces:**
- Keep: `start`, `kill`, `pane_base_index`, `select_pane`
- Remove: `send_keys`, `split`, `open_debug_layout`
- Add:
  - `current_pane_id() -> str`
  - `run_in_new_pane(*, target: int | str, direction: Literal["h","v"], percent: int, cmd: str) -> str`
  - `respawn_pane(*, pane: str, cmd: str) -> None`
  - `pane_exists(pane: str) -> bool`
  - `get_option(name: str) -> str`
  - `set_option(name: str, value: str) -> None`
  - `unset_option(name: str) -> None`
  - `display_message(message: str) -> None`
  - `set_remain_on_exit(pane: str) -> None`

- [ ] **Step 1: Replace old Session tests with process-pane/state tests**

Update `tests/test_session.py`:
- Delete tests for `split`, `send_keys`, and `open_debug_layout`.
- Keep `select_pane`, nonzero runner, and `pane_base_index` fallback tests.
- Add tests:
  - `run_in_new_pane` calls:
    `tmux split-window -d -P -F "#{pane_id}" -h -p 66 -t %1 "tmux set-option -p remain-on-exit on; exec <cmd>"`
    and returns `%2`.
  - `respawn_pane` reasserts `remain-on-exit on`, then calls `tmux respawn-pane -k -t %2 <cmd>`.
  - `current_pane_id` queries `tmux display-message -p "#{pane_id}"`.
  - `get_option` queries `tmux show-option -qv @likedbg_workspace`; `set_option` and `unset_option` call tmux session options.
  - `pane_exists("%2")` returns true on runner rc 0 and false on rc nonzero.
  - `display_message` calls `tmux display-message <message>`.
  - `Session` has no `send_keys`, `split`, or `open_debug_layout` attributes.

- [ ] **Step 2: Run to verify failures**

Run: `uv run pytest tests/test_session.py -q`

Expected: FAIL because the new methods do not exist and old methods still exist.

- [ ] **Step 3: Implement `Session` methods**

Implementation notes:
- `run_in_new_pane` uses `_query(...)` for `split-window -d -P -F "#{pane_id}" ... wrapped_cmd`, where
  `wrapped_cmd = "tmux set-option -p remain-on-exit on; exec <cmd>"`. This avoids a fast-exit race before the
  parent could set pane-local options.
- `respawn_pane` calls `set_remain_on_exit(pane)` before `_tmux("respawn-pane", "-k", "-t", pane, cmd)`.
- `pane_exists` should use runner return code, not `_query`, so stale pane checks are explicit.
- `get_option` should return `""` for missing options.
- `set_option`/`unset_option` operate on the current tmux session, not `-g`.
- Keep `_tmux` as the typed-error wrapper for commands where nonzero is fatal.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_session.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/session.py tests/test_session.py
git commit -m "feat(session): process-pane and tmux state primitives"
```

---

### Task 2: Stage launch callbacks and process-pane CLI assembly

**Files:**
- Modify: `src/likedbg/stages/debuggee.py`
- Modify: `src/likedbg/stages/debugger.py`
- Modify: `src/likedbg/cli.py`
- Modify: `tests/test_stage_debuggee.py`
- Modify: `tests/test_stage_debugger.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- `DebuggeeStage(*, launch: Callable[[str], None], debuggee_image: str)`
- `DebuggerStage` keeps `run_gdb: Callable[[list[str]], None]`; CLI `run_gdb` launches the pane command.
- `build_pipeline`/`build_use_pipeline` no longer accept `panes`.
- Initial launch stores:
  - `@likedbg_workspace`
  - `@likedbg_base_pane_id`
  - `@likedbg_debuggee_cmd`
  - `@likedbg_debugger_cmd`
  - `@likedbg_debuggee_pane`
  - `@likedbg_debugger_pane`
  - clears stale `@likedbg_restart_in_progress`

- [ ] **Step 1: Update stage tests for `launch` wording**

In `tests/test_stage_debuggee.py`, rename fake `sent` to `launched` if desired and construct `DebuggeeStage(launch=...)`.

Expected command assertions stay the same:
- native Debuggee command starts with host QEMU and has no `docker run`
- in-container command wraps `docker run`
- Linux host network/KVM behavior stays unchanged

In `tests/test_stage_debugger.py`, keep `run_gdb` tests; no command behavior changes.

- [ ] **Step 2: Update CLI assembly tests**

Add a fake `Session`/recorder in `tests/test_cli.py` that records:
- `current_pane_id() -> "%1"`
- `run_in_new_pane(...)` calls and returns `%2`, then `%3`
- `set_option(...)` calls
- `unset_option("@likedbg_restart_in_progress")`

Update:
- `test_build_pipeline_includes_all_stage_names`: call `build_pipeline(..., session=session, ...)` without `panes`.
- `test_build_use_pipeline_is_launch_only`: same.
- Add a test that runs the Debuggee/Debugger stages from the built pipeline with a prepared `PipelineContext` and asserts:
  - Debuggee launches with `target="%1"`, `direction="h"`, `percent=66`
  - Debugger launches with `target="%2"`, `direction="v"`, `percent=50`
  - `@likedbg_base_pane_id == "%1"`
  - `@likedbg_workspace == str(tmp_path)`
  - `@likedbg_debuggee_cmd` and `@likedbg_debugger_cmd` are stored
  - `@likedbg_debuggee_pane == "%2"` and `@likedbg_debugger_pane == "%3"`
  - stale restart lock is cleared before writing fresh session state

- [ ] **Step 3: Run to verify failures**

Run:
```bash
uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py tests/test_cli.py -q
```

Expected: FAIL because `DebuggeeStage` still takes `send`, CLI still takes `panes`, and state storage does not exist.

- [ ] **Step 4: Implement**

Implementation notes:
- In `DebuggeeStage`, rename constructor arg/field from `send` to `launch`; call `self._launch(cmd)`.
- In CLI pipeline builders:
  - compute `base = session.current_pane_id()`
  - clear stale lock via `session.unset_option("@likedbg_restart_in_progress")`
  - store workspace/base before stages can launch
  - `launch_debuggee(cmd)` stores `@likedbg_debuggee_cmd`, creates the pane, stores `@likedbg_debuggee_pane`
  - `run_gdb(args)` builds `gdb_pane_command(...)`, stores `@likedbg_debugger_cmd`, creates the pane under the Debuggee pane, stores `@likedbg_debugger_pane`
- `cmd_use` and `main` no longer call `open_debug_layout()` and no longer pass `panes`.
- Keep `session.start("LIKE-DBG")` before `current_pane_id()`.

- [ ] **Step 5: Run tests**

Run:
```bash
uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py tests/test_cli.py tests/test_session.py -q
```

Expected: PASS.

- [ ] **Step 6: Gate + commit**

```bash
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q
git add src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py src/likedbg/cli.py tests/test_stage_debuggee.py tests/test_stage_debugger.py tests/test_cli.py
git commit -m "feat(cli): launch debug panes as tmux process panes"
```

---

### Task 3: `--restart-debuggee` CLI control

**Files:**
- Modify: `src/likedbg/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- CLI flag: `--restart-debuggee`
- New command helper: `cmd_restart_debuggee(session: Session) -> int`
- Dispatch happens immediately after argument parsing/log setup and before config loading, Docker client creation, image checks, version resolution, or recipe construction.

- [ ] **Step 1: Write restart tests**

In `tests/test_cli.py`, add a restart fake session with methods from Task 1 and tests:

- `test_restart_debuggee_respawns_existing_pane_in_place`:
  - options contain workspace, debuggee command, debuggee pane `%2`, base `%1`
  - `pane_exists("%2")` true
  - `cmd_restart_debuggee` sets lock, calls `respawn_pane(pane="%2", cmd=<stored>)`, reasserts remain through `Session.respawn_pane`, restores active pane, clears lock
  - no split occurs; `@likedbg_debuggee_pane` remains `%2`

- `test_restart_debuggee_recreates_when_debuggee_pane_stale`:
  - `pane_exists("%2")` false, `pane_exists("%1")` true
  - captures active `%3`, calls `run_in_new_pane(target="%1", direction="h", percent=66, cmd=<stored>) -> "%4"`
  - stores `@likedbg_debuggee_pane="%4"` and selects active `%3` afterward

- `test_restart_debuggee_missing_command_or_workspace_raises_remedy`:
  - missing `@likedbg_debuggee_cmd` or `@likedbg_workspace` raises `SessionError` with remedy to start a fresh Debugging session.

- `test_restart_debuggee_missing_base_only_fatal_for_recreate`:
  - existing Debuggee pane path does not need base.
  - stale Debuggee + missing/stale base raises `SessionError`.

- `test_restart_debuggee_lock_prevents_double_tap`:
  - if `@likedbg_restart_in_progress == "1"`, returns/raises with `LIKE-DBG restart already in progress`
  - no respawn/split calls.

- `test_restart_debuggee_preserves_focus_when_active_pane_still_exists`:
  - active pane restored after respawn and recreate.

- `test_main_restart_bypasses_config_and_docker`:
  - monkeypatch `load_settings`, Docker creation, and image helpers to fail if called.
  - `main(["--restart-debuggee"])` calls restart path only.

- `test_main_restart_failure_displays_tmux_message`:
  - force `cmd_restart_debuggee` to raise `SessionError("missing ...")`.
  - assert `display_message("LIKE-DBG restart failed: ...")` is called and rc is nonzero.

- [ ] **Step 2: Run to verify failures**

Run: `uv run pytest tests/test_cli.py -k "restart_debuggee or main_restart" -q`

Expected: FAIL (`--restart-debuggee` and helper do not exist).

- [ ] **Step 3: Implement restart**

Implementation shape:

```python
def cmd_restart_debuggee(session: Session) -> int:
    if session.get_option("@likedbg_restart_in_progress") == "1":
        raise SessionError("LIKE-DBG restart already in progress")
    acquired = False
    session.set_option("@likedbg_restart_in_progress", "1")
    acquired = True
    try:
        workspace = session.get_option("@likedbg_workspace")
        cmd = session.get_option("@likedbg_debuggee_cmd")
        debuggee = session.get_option("@likedbg_debuggee_pane")
        base = session.get_option("@likedbg_base_pane_id")
        if not workspace or not cmd:
            raise SessionError(..., remedy="start a fresh Debugging session with `uv run ./start_kgdb`")
        active = session.current_pane_id()
        if debuggee and session.pane_exists(debuggee):
            session.respawn_pane(pane=debuggee, cmd=cmd)
        else:
            if not base or not session.pane_exists(base):
                raise SessionError(..., remedy="start a fresh Debugging session with `uv run ./start_kgdb`")
            new_debuggee = session.run_in_new_pane(target=base, direction="h", percent=66, cmd=cmd)
            session.set_option("@likedbg_debuggee_pane", new_debuggee)
        if active and session.pane_exists(active):
            session.select_pane(active)
        return 0
    finally:
        if acquired:
            session.unset_option("@likedbg_restart_in_progress")
```

CLI dispatch:
- add `parser.add_argument("--restart-debuggee", action="store_true")`
- after `logsetup.configure_stderr(...)`, if restart:
  - require `$TMUX` (return 2 with error if absent)
  - create `Session("LIKE-DBG")`
  - call `cmd_restart_debuggee`
  - on `LikeDbgError`, log error and call `session.display_message(f"LIKE-DBG restart failed: {exc.message}")` best-effort
  - return 1
- Do not load settings or create Docker client on this path.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_cli.py tests/test_session.py -q`

Expected: PASS.

- [ ] **Step 5: Gate + commit**

```bash
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): restart Debuggee process pane from tmux state"
```

---

### Task 4: GDB `likedbg-reconnect` helper

**Files:**
- Modify: `src/likedbg/gdbcmd.py`
- Modify: `tests/test_gdbcmd.py`

**Interfaces:**
- `build_gdb_args(...)` adds extension-aware helper definitions before/alongside the initial attach.
- Helper name: `likedbg-reconnect`
- Behavior: attempt `disconnect` while tolerating no target, then reconnect with extension-specific command; no auto-continue; no initial breakpoint reapplication.

- [ ] **Step 1: Write tests**

Add tests in `tests/test_gdbcmd.py`:
- GEF args contain a `likedbg-reconnect` helper and `gef-remote <addr> <port>` inside it.
- pwndbg args contain a `likedbg-reconnect` helper and `target remote <addr>:<port>` inside it.
- Helper text attempts `disconnect` before reconnect and tolerates failure/no target.
- Helper does not contain `continue`, `hbreak start_kernel`, or `break start_kernel`.
- Existing initial launch behavior still contains initial attach, optional `hbreak start_kernel`, and optional `continue` when `breakpoint` is not `None`.

- [ ] **Step 2: Run to verify failures**

Run: `uv run pytest tests/test_gdbcmd.py -q`

Expected: FAIL because no helper exists.

- [ ] **Step 3: Implement**

Implementation options:
- Keep it simple with `-ex` commands that define a GDB user command:
  - `define likedbg-reconnect`
  - `disconnect`
  - extension-specific remote command
  - `end`
- If raw `disconnect` on no target would be noisy/fatal, wrap with Python or `set confirm off`/documented GDB tolerance. Tests should pin the chosen shape.
- Do not add aliases.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_gdbcmd.py tests/test_stage_debugger.py tests/test_launchers.py -q`

Expected: PASS.

- [ ] **Step 5: Gate + commit**

```bash
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q
git add src/likedbg/gdbcmd.py tests/test_gdbcmd.py
git commit -m "feat(gdb): add likedbg-reconnect helper"
```

---

### Task 5: Refresh project `.tmux.conf` and README usage

**Files:**
- Modify: `.tmux.conf`
- Modify: `README.md`

**Behavior:**
- Keep it self-contained and portable: no TPM, no plugins, no external clipboard tools.
- Prefix: default `C-b`; leave `C-a` available for QEMU/serial control.
- Indexes: `base-index 1`, `pane-base-index 1`.
- Navigation: `prefix+h/j/k/l`, Alt-arrows; repeatable uppercase `H/J/K/L` resize.
- Splits/windows preserve path: `prefix+|`, `prefix+-`, `prefix+c`.
- Mouse on; vi copy-mode; large scrollback; truecolor; focus events; bottom status.
- Stable names: `allow-rename off`, `automatic-rename off`.
- `detach-on-destroy off`.
- Status line: ASCII separators, balanced colors, active-window contrast, no permanent shortcut hint.
- LIKE-DBG binding:
  ```tmux
  bind B run-shell -b 'if [ -n "#{@likedbg_workspace}" ]; then cd "#{@likedbg_workspace}" || { tmux display-message "LIKE-DBG restart failed: workspace unavailable"; exit 1; }; uv run ./start_kgdb --restart-debuggee; else tmux display-message "LIKE-DBG restart failed: missing @likedbg_workspace"; fi'
  ```
- Keep `prefix+?` default help intact.

- [ ] **Step 1: Replace `.tmux.conf` with a curated built-in-only config**

Use the current file as source material, but remove:
- TPM/plugin declarations and `run '~/.tmux/plugins/tpm/tpm'`
- vim-aware pane-navigation shell logic
- external clipboard helper bindings
- `C-s` prefix customization
- obsolete comments that contradict current behavior

Add comments for:
- `C-b B` restart Debuggee
- no plugins required
- `C-a` left available for QEMU/serial control

- [ ] **Step 2: Update README**

README changes:
- Keep recommending `tmux -f .tmux.conf`.
- Replace old `poetry` usage with current `uv run ./start_kgdb` if this README section is already stale in nearby text.
- Remove the old warning that custom tmux config must start first pane at `0`; the app queries pane base index and the project config uses 1-based indexes.
- Document:
  - `C-b B` restarts Debuggee in the project tmux config
  - custom tmux users can run `uv run ./start_kgdb --restart-debuggee` or add their own binding

- [ ] **Step 3: Syntax-check tmux config**

Run: `tmux -f .tmux.conf start-server \; source-file .tmux.conf \; kill-server`

Expected: exits 0.

If this fails due an active tmux server/socket issue, use a temporary socket:
`tmux -L likedbg-plan-check -f .tmux.conf start-server \; source-file .tmux.conf \; kill-server`

- [ ] **Step 4: Commit**

```bash
git add .tmux.conf README.md
git commit -m "feat(tmux): ship self-contained LIKE-DBG workflow config"
```

---

### Task 6: ADR-0005 — process panes and restart control

**Files:**
- Create: `docs/adr/0005-debug-pane-process-isolation.md`

**Content:**
- Decision: debug panes are process panes, not interactive shells fed by `send-keys`.
- Consequences:
  - no shell-history pollution
  - no post-exit shell in Debuggee/Debugger panes
  - `remain-on-exit` keeps crash/exit output visible
  - restart control uses stored tmux session state and `respawn-pane -k`
  - checked-in `.tmux.conf` owns the recommended key binding; runtime code does not mutate user bindings
- Considered/rejected:
  - `HISTFILE=/dev/null`/history-off in pane shells
  - continuing to use `send-keys`
  - runtime `bind-key` mutation
  - global `remain-on-exit`

- [ ] **Step 1: Write ADR**

Follow the concise style of ADR-0003/0004.

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0005-debug-pane-process-isolation.md
git commit -m "docs(adr): record debug pane process isolation"
```

---

### Task 7: Final gate and live verification

**Files:**
- No planned source edits unless live verification finds bugs.

- [ ] **Step 1: Full local gate**

Run:
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src/likedbg
uv run pytest -q
```

Expected: all green.

- [ ] **Step 2: Live tmux config smoke**

Run in a fresh project tmux session:
```bash
tmux -f .tmux.conf
```

Verify:
- prefix is `C-b`
- `C-b ?` shows normal tmux help and includes `B`
- mouse, vi copy-mode, pane movement, resize, splits, and status line are usable
- no plugin install step is required

- [ ] **Step 3: Live LIKE-DBG run**

Inside that tmux session:
```bash
uv run ./start_kgdb
```

Verify:
- base shell history contains only the user command, not QEMU/GDB `docker run` internals.
- Debuggee pane and Debugger pane are process panes; exiting QEMU/GDB leaves pane output visible.
- Geometry remains the expected control/QEMU/GDB three-pane layout.

- [ ] **Step 4: Restart Debuggee live gate**

From the Debugger pane:
- press `C-b B`
- confirm focus remains in the Debugger pane
- confirm Debuggee restarts in place via `respawn-pane -k` and layout is preserved
- run `likedbg-reconnect` in GDB
- choose when to `continue`
- double-tap `C-b B` and confirm `LIKE-DBG restart already in progress` rather than duplicate panes
- manually close the Debuggee pane, press `C-b B`, and confirm fallback recreate from base pane works and restores focus

- [ ] **Step 5: Custom tmux fallback**

In a normal/custom tmux session without the project config:
```bash
uv run ./start_kgdb --restart-debuggee
```

Verify the CLI path works from stored tmux state and LIKE-DBG does not mutate user key bindings.

- [ ] **Step 6: Final commit if fixes were needed**

If live-gate fixes were required, commit only the touched files with a focused message.

---

## Spec Coverage

- §3.4 `Session` process panes → Task 1
- §3.5 stage/CLI process-pane wiring → Task 2
- Restart Debuggee state/control/focus/layout/locking → Task 3
- `likedbg-reconnect` → Task 4
- Project `.tmux.conf` modernization + `C-b B` → Task 5
- ADR-0005 → Task 6
- Regression/live gates → Task 7

All Plan 2 decisions from `docs/superpowers/specs/2026-06-24-logging-session-ergonomics-design.md` are covered. Plan 1 observability/logging work remains excluded.
