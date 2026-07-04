# Crash Intelligence — Design (Branch 1 `feat/crash-intel`)

**Date:** 2026-07-04
**Sub-project:** B (Modern debugging UX) — slice **B3** (crash/oops detector) **+** panic→auto-break.
**Branch:** `feat/crash-intel` (off `dev`, merged locally per the hard rule).
**Status:** design approved via brainstorming (2026-07-04); pending user review → writing-plans.

## 1. Purpose

Kernel exploitation is an edit → deploy → **crash** → root-cause loop. Today a crash scrolls past
in the QEMU pane and is gone. This slice makes a crash a first-class, symbolized artifact **and**
drops the operator at the fault with live state:

1. **Panic→auto-break** — gdb halts at the faulting site (with registers) the instant the kernel
   faults, instead of after the trace has scrolled by.
2. **Crash/oops detector** — every run produces a symbolized `crash.json` + blog-ready `crash.md`
   from the guest console, enriched with gdb's live view when it trapped the fault.

These two are bundled because they fuse: the console scrape is the always-there baseline; the
gdb-live snapshot is what makes the report blog-grade. Serves the project goal (bugs + blog posts).

## 2. Goals / non-goals

**Goals (v1, both arches — arm64 daily driver + x86_64, which is what LK01 / most kernel-exploit
content targets):**
- Byte-perfect guest console capture, independent of the human tmux pane.
- Detect + classify: panic, general oops/`BUG`, KASAN, UBSAN, x86 `#GP`, page-fault oops,
  arm64 kernel abort, `WARN`; plus generic call-trace extraction.
- Symbolize `func+off` (pure Python via `System.map`) and merge gdb-live `file:line`/registers.
- `crash.json` (structured) + `crash.md` (human/blog). Capture all crash events in a run; the first
  fatal one is `primary`.
- gdb halts at a curated, crash-only breakpoint set with live registers available.
- On-demand `--analyze-crash [run-id]` (pure host, Docker/tmux-free) + auto-analyze at teardown.

**Non-goals (deferred, clean future adds — NOT this branch):**
- Soft/non-fatal liveness bugs: hung task, soft/hard lockup, RCU stall (different lifecycle;
  console keeps flowing).
- Live watcher tailing `console.raw` in real time + real-time `run.json` → `crashed` status flip.
- Cross-run crash dedup / triage (Sub-project D / syzkaller territory).
- Deep `addr2line`/DWARF `file:line` for **non-trapped** frames (gdb-live already gives `file:line`
  for the trapped frame; System.map gives `func+off` for all). Optional later enrichment.

## 3. Decisions (brainstorm 2026-07-04)

All five keystone questions resolved to the recommended option:

1. **Serial substrate = dedicated sink.** QEMU tees the console to a run-dir file `logs/console.raw`
   via the serial **chardev `logfile=`** option — byte-perfect, restart-stable, identical in
   native-HVF and in-container modes. The human tmux pane is unchanged. (Not a second UART: `logfile=`
   duplicates the *same* console to a file while stdio still drives the pane.) Rationale: the parser's
   reliability and blog-ready logs must not be hostage to tmux pane quirks (CRLF, `C-b B` restart
   gaps, gdb interleave).
2. **Report source = both, merged.** Console-scrape is the always-on, headless-safe baseline;
   gdb-live (`bt`/registers/faulting-addr at the panic-break trap) is merged in when present.
3. **Trigger = pure analyzer + auto-at-teardown.** A pure `console.raw → CrashReport` core, exposed
   as `--analyze-crash [run-id]` (default `latest`) and auto-fired at teardown. Live watcher deferred.
4. **Panic-break = curated crash-only set, default-ON, configurable.** Symbols that execute *only*
   on a real fault (zero perf cost, no spurious stops): `panic`, `die` (carries faulting `pt_regs`
   on both arches), `oops_enter`, `kasan_report`, UBSAN handlers. Missing symbols tolerated. Software
   `break` (hbreak stays for early boot). Toggle + symbol list overridable via `[debugger]`.
5. **Scope = both arches + the class set above + WARN; single-run report; multi-event capture.**

Architecture choice: **Approach 1** — pure-core analyzer + gdb-side capture module + a **narrow rw
crash-drop mount** (just `<run>/crash/`, rest of the workspace stays `:ro`) so gdb-live output is
clean structured JSON rather than scraped pane text.

## 4. Architecture

### 4.1 Division of labor
- **gdb side stays dumb:** dumps live state as JSON. Because gdb has `vmlinux` loaded, its `bt` is
  already source-symbolized. Runs inside the debugger container (our `likedbg` package is NOT
  available there → the capture logic is self-contained embedded Python, like today's
  `LikedbgReconnect`).
- **Host side is smart:** owns console parsing, `System.map` symbolization, merge, and rendering.

### 4.2 New pure core — `crash/` subpackage (deep, I/O-free)
- `crash/model.py` — `CrashReport`, `CrashEvent`, `Frame`, `Registers`, `KasanInfo` dataclasses with
  `to_dict()`.
- `crash/parse.py` — `parse_console(text: str, arch: str) -> list[CrashEvent]`. CRLF-normalize first
  (known tty gotcha — see `reference-tty-container-crlf` / the B1 `.config` fix), then arch-aware
  classification + extraction (trigger line, fault addr/PC, register block, call-trace frames). Thin
  arch-specific layer for the register/fault-line formats (arm64 `pc :`/`lr :`, x86 `RIP:`/`RSP:`;
  arm64 "Unable to handle kernel …", x86 "BUG: unable to handle page fault …").
- `crash/symbolize.py` — `load_system_map(path) -> SymbolTable`; `symbolize(event, symtab)` resolves
  `func+off` → symbol/address in pure Python (no host toolchain); merges gdb-live `file:line` where
  present.
- `crash/render.py` — `render_json(report) -> dict`, `render_markdown(report) -> str`.

### 4.3 Thin impure shell
- `crash/analyze.py` — `analyze_run(run_dir) -> CrashReport`: reads `console.raw` + optional
  `crash.gdb.json`, runs parse → symbolize → merge → render, writes `crash.json` + `crash.md`,
  updates `run.json`. Single entry point for both `--analyze-crash` and teardown.

### 4.4 Edits to existing modules (small, at established seams)
- `qemu.py` (`build_qemu_argv`) — serial chardev gains `logfile=<run>/logs/console.raw`; needs the
  console path threaded in from the recorder/context.
- `launchers.py` — `qemu_container_command` adds an rw mount for the run's `logs/` (so in-container
  QEMU can write the log); `gdb_pane_command` adds a narrow rw mount for `<run>/crash/`.
- `gdbcmd.py` — the embedded gdb-Python payload gains a self-contained `CrashCapture` breakpoint
  class; the crash symbol list is injected from config at arg-build time.
- `stages/debuggee.py` / `stages/debugger.py` — thread the console path / crash-drop path + crash
  symbol list + `break_on_crash` flag.
- `run_artifacts.py` (`RunRecorder`) — expose `console_raw` and `crash_dir` paths; pre-create both in
  `start`; `run.json` gains crash summary fields; teardown analyze hook.
- `config.py`, `cli.py` — config knobs + `--analyze-crash`.

## 5. Data flow (end to end)

1. `RunRecorder.start` pre-creates `logs/console.raw` and `crash/`.
2. Debuggee stage → QEMU tees console to the pane **and** byte-logs to `console.raw` (native: host
   path; in-container: run `logs/` mounted rw, identical path under the colima share).
3. Debugger stage → gdb attaches, installs `likedbg-reconnect` + `CrashCapture` breakpoints on the
   curated symbols, with `crash/` mounted rw.
4. **Crash** → a curated breakpoint hits → gdb halts (operator lands at the fault with registers)
   **and** `CrashCapture.stop()` writes `crash/crash.gdb.json`, prints a marker, returns `True`.
5. `analyze_run` (teardown or on demand) → parse `console.raw` → symbolize via `System.map` → merge
   `crash.gdb.json` → write `crash.json` + `crash.md`, update `run.json`.
6. `--analyze-crash [run-id]` re-runs step 5 on any saved run — pure host, no Docker/tmux.

## 6. `crash.json` schema

```json
{
  "schema_version": 1,
  "run_id": "…", "build_label": "…", "arch": "x86_64|arm64",
  "kernel_release": "6.6.30", "generated_at": "…",
  "sources": ["console", "gdb-live"],
  "primary": 0,
  "events": [{
    "class": "kasan|oops|panic|ubsan|gp-fault|page-fault|arm64-abort|warn",
    "fatal": true,
    "incomplete": false,
    "title": "BUG: KASAN: use-after-free in list_del…",
    "fault_addr": "0xffff…",
    "fault_pc": {"raw":"func+0x12/0x34","symbol":"func","offset":18,"file":"mm/x.c","line":123},
    "access": {"type":"read|write","size":8},
    "registers": {"pc":"…","sp":"…","…":"…"},
    "trace": [{"raw":"func+0x/0x","symbol":"…","offset":0,"file":"…","line":0}],
    "gdb_live": {"stopped_at":"die","registers":{"…":"…"},"backtrace":["…"]},
    "source": ["console","gdb-live"]
  }]
}
```

`crash.md` is a human/blog-ready rendering of the same object.

## 7. Panic-break gdb integration

- Embedded payload gains `CrashCapture(gdb.Breakpoint)` installed on each configured crash symbol.
  Each install wrapped so **missing symbols are tolerated** (no error when KASAN/UBSAN absent).
- Runtime faults (MMU on) → plain software `break`; `hbreak` stays for early boot / `start_kernel`.
- `stop()` captures: stopped symbol, register set, gdb-symbolized `bt`, and — for `die` — the
  `pt_regs` argument (faulting context); for `kasan_report` the access details it can read. Writes
  `crash/crash.gdb.json`, prints a one-line marker, returns `True` so gdb halts.
- Symbol list injected from `[debugger] crash_breakpoints` at arg-build time → overridable without
  code changes.

## 8. Config surface

- `[debuggee] capture_console = true` — the `logfile=` console sink (default on; harmless).
- `[debugger] break_on_crash = true` — install `CrashCapture` breakpoints (default on).
- `[debugger] crash_breakpoints = ["panic","die","oops_enter","kasan_report",
  "__ubsan_handle_out_of_bounds", …]` — curated default set, fully overridable. Arch-aware default.

Toggles sit on the axis that owns the behavior (QEMU→`[debuggee]`, gdb→`[debugger]`), matching the
existing config shape.

## 9. CLI + teardown

- **`--analyze-crash [RUN-ID]`** — `nargs="?"`, `const="latest"`. Pure host, Docker/tmux-free (same
  class as `--explain-config`): writes `crash.json`/`crash.md`, prints a short summary (class, title,
  primary faulting frame, paths). Re-runnable on any archived run.
- **Auto at teardown** — the Debuggee pane command gets the host analyzer
  (`start_kgdb --analyze-crash <run-id>`) appended after the QEMU invocation, so when QEMU exits
  (guest reboot/quit) the report is generated in place (pane already has `remain-on-exit`; the pane
  returns to a host shell in both native and in-container modes, so it is always the host CLI that
  runs — no cross-container shelling). For the **gdb-trapped** case QEMU does not exit, but
  `crash.gdb.json` is on disk the instant the breakpoint hits → merged report on the next
  `--analyze-crash`/teardown.

## 10. Error handling / edge cases

- No `console.raw` / empty / no crash signature → clean "no crash detected" (exit 0, no report file),
  never an error.
- Truncated crash block (rebooted mid-print) → best-effort parse; event flagged `incomplete`.
- `crash.gdb.json` absent (headless / `break_on_crash=false` / never trapped) → console-only report.
- `System.map` missing → skip enrichment, keep raw `func+off`.
- Missing gdb crash symbols → tolerated (§7).
- Panic reboot: `console.raw` already holds the dump (logged before reboot), so headless scraping
  works; with gdb attached the crash breakpoint holds the guest before reboot. `oops=panic` already
  set upstream (oops→panic).
- rw crash-drop dir created by `RunRecorder.start` before the container launches.

## 11. Testing + live gate

- **Unit (bulk, deterministic, no Docker):** `parse_console` against captured real fixtures for every
  class × both arches; `symbolize` against a fixture `System.map`; `render_markdown` snapshot tests;
  `analyze_run` against a fixture run dir (`console.raw` + `crash.gdb.json`) → merged `crash.json`.
- **Unit (wiring):** qemu argv contains the `logfile=` chardev; container commands contain the rw
  mounts; gdb args contain the crash breakpoints from config; config knobs parse + default correctly.
- **Live gate (both arches, per project discipline):** trigger real crashes —
  `echo c > /proc/sysrq-trigger` (panic), an in-tree `lib/test_kasan` UAF or a tiny null-deref module
  (oops) — and confirm: gdb halts at the fault with live registers, `console.raw` captured,
  `crash.json`/`crash.md` produced with a symbolized trace. M5 (arm64) + Ubuntu VM / in-container
  (x86_64).

## 12. Risks / open items

- **Console `logfile=` in-container path:** the run `logs/` dir must be writable by the in-container
  QEMU; confirm the mount + path identity under colima's share (native mode is trivial). Validate at
  the live gate.
- **`die` `pt_regs` extraction in gdb:** reading the argument reliably across arches/inlining may need
  a fallback to `$pc`/`$sp` frame registers if the arg isn't resolvable.
- **KASAN report shape** varies by kernel version; parser fixtures should pin the 6.6.x format and
  degrade gracefully on drift.
- **Cache sensitivity:** enabling sanitizer profiles for the live gate forces kernel rebuilds
  (ADR-0003 content-hash); expected, not a regression.

## 13. Glossary / ADR touch-ups (in the plan)

- CONTEXT.md: add **Crash report** (and note `console.raw` as the byte-perfect serial sink vs the
  human pane transcript).
- No new ADR expected (realizes the existing run-artifacts/observability direction); revisit if the
  rw crash-drop mount warrants recording as a decision.
