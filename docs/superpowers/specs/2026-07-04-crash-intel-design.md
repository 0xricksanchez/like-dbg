# Crash Intelligence — Design (Branch 1 `feat/crash-intel`)

**Date:** 2026-07-04 (grill-with-docs pass folded in same day)
**Sub-project:** B (Modern debugging UX) — slice **B3** (crash/oops detector) **+** panic→auto-break.
**Branch:** `feat/crash-intel` (off `dev`, merged locally per the hard rule).
**Status:** design approved via brainstorming + sharpened via grill-with-docs (2026-07-04); pending
user review → writing-plans.
**Decisions recorded in:** ADR-0007; CONTEXT.md glossary (**Console log**, **Crash report**, extended
**Run artifact** status).

## 1. Purpose

Kernel exploitation is an edit → deploy → **crash** → root-cause loop. Today a crash scrolls past in
the QEMU pane and is gone. This slice makes a crash a first-class, symbolized artifact **and** drops
the operator at the fault with live state:

1. **Panic→auto-break** — gdb halts at the faulting site (with registers) the instant the kernel
   faults, instead of after the trace has scrolled by.
2. **Crash/oops detector** — every run produces a symbolized `crash.json` + blog-ready `crash.md`
   from the Console log, enriched with gdb's live view when it trapped the fault.

Bundled because they fuse: the console scrape is the always-there baseline; the gdb-live snapshot is
what makes the report blog-grade. Serves the project goal (bugs + blog posts).

## 2. Goals / non-goals

**Goals (v1, both arches — arm64 daily driver + x86_64, which is what LK01 / most kernel-exploit
content targets):**
- Byte-exact guest **Console log** (`logs/console.raw`), independent of the human tmux pane.
- Detect + classify: panic, general oops/`BUG`, KASAN, UBSAN, x86 `#GP`, page-fault oops, arm64
  kernel abort, `WARN`; plus generic call-trace extraction.
- Symbolize from the kernel's own `CONFIG_KALLSYMS` frames (present in the base profile) + gdb-live
  `file:line`/registers for the trapped frame. Graceful raw-address degrade when KALLSYMS is off.
- `crash.json` (structured) + `crash.md` (human/blog). Capture all crash events; first fatal is
  `primary`.
- gdb halts at a curated, crash-only breakpoint set with live registers available.
- On-demand `--analyze-crash [run-id]` (pure host, Docker/tmux-free) as the primary trigger; a tmux
  `pane-died` hook auto-analyzes the QEMU-exit subset.
- Add a **soft** `CONFIG_KALLSYMS` expectation to crash-relevant profiles.

**Non-goals (deferred — NOT this branch):**
- `System.map`/`addr2line` raw-address + non-trapped-frame `file:line` resolution (optional
  enrichment; see ADR-0007 for why it is deferred, not core).
- Soft/non-fatal liveness bugs: hung task, soft/hard lockup, RCU stall (different lifecycle).
- Live watcher tailing `console.raw` in real time (the `crashed` status is set post-hoc by
  `analyze_run`, not via a real-time watcher).
- Run-completion/exit lifecycle states (belong to B5).
- Cross-run crash dedup / triage (Sub-project D / syzkaller territory).
- HMP/QMP monitor access during a run (dedicated socket arrives with B5).

## 3. Decisions

Keystones (brainstorm) — all resolved to the recommended option; the grill-with-docs pass (§14)
sharpened each against the code + docs.

1. **Serial substrate = dedicated pure-serial sink.** Replace bare `-nographic` (which expands to a
   muxed `-serial mon:stdio`) with an explicit
   `-chardev stdio,id=cons,logfile=<run>/logs/console.raw,signal=off -serial chardev:cons -display none`.
   The guest console still drives the tmux pane (stdio) **and** is byte-logged to the Console log.
   The stdio HMP monitor is **dropped** so `console.raw` stays pure serial (no monitor interleave);
   control is via gdb, and B5 adds HMP/QMP on a dedicated socket. Identical wiring native-HVF and
   in-container (in-container just needs the run's `logs/` mounted rw). ADR-0007.
2. **Report source = both, merged.** Console-scrape (KALLSYMS-symbolic) is the always-on, headless-safe
   baseline; gdb-live (`bt`/registers/faulting-addr at the panic-break trap) is merged when present.
3. **Symbolization = KALLSYMS + gdb-live; System.map deferred.** The base profile sets
   `CONFIG_KALLSYMS`, so console frames arrive symbolic (`func+off`); gdb-live supplies `file:line`
   for the trapped frame. `System.map` is *not* on the host in volume mode, so leaning on it would
   break pure-host `--analyze-crash`; it becomes optional enrichment. ADR-0007.
4. **Trigger = pure analyzer, manual-primary + `pane-died` hook.** A pure `console.raw → CrashReport`
   core, exposed as `--analyze-crash [run-id]` (default `latest`) — the primary path for the
   panic-break-trap workflow (QEMU stays running, so nothing "tears down"). A tmux `pane-died` hook in
   `.tmux.conf` auto-analyzes the QEMU-exit subset (reboot/quit). Real-time flip deferred (live watcher).
5. **Panic-break = curated crash-only, arch-independent, default-ON, configurable.** Symbols that run
   *only* on a real fault (zero perf cost): `panic`, `die` (faulting `pt_regs`, universal fatal
   chokepoint on both arches), `oops_enter`, `kasan_report`, `ubsan_epilogue`. Missing symbols
   tolerated. Software `break` (hbreak stays for early boot). Toggle + list overridable via `[debugger]`.
6. **Scope = both arches + the class set above + WARN; single-run report; multi-event capture.**

Architecture: **Approach 1** — pure-core analyzer + gdb-side capture module + a **narrow rw crash-drop
mount** (just `<run>/crash/`; the rest of the workspace stays `:ro`) so gdb-live output is clean
structured JSON rather than scraped pane text.

## 4. Architecture

### 4.1 Division of labor
- **gdb side stays dumb:** dumps live state as JSON. It has `vmlinux` loaded so its `bt` is already
  source-symbolized. Runs in the debugger container (our `likedbg` package is NOT available there →
  self-contained embedded Python, like today's `LikedbgReconnect`).
- **Host side is smart:** owns console parsing, merge, and rendering.

### 4.2 New pure core — `crash/` subpackage (deep, I/O-free)
- `crash/model.py` — `CrashReport`, `CrashEvent`, `Frame`, `Registers`, `KasanInfo` dataclasses with
  `to_dict()`.
- `crash/parse.py` — `parse_console(text: str, arch: str) -> list[CrashEvent]`. CRLF-normalize first
  (tty gotcha — `reference-tty-container-crlf` / the B1 `.config` fix), then arch-aware classification
  + extraction (trigger line, fault addr/PC, register block, call-trace frames). The frames are taken
  as the kernel already symbolized them (`func+off`); raw-hex frames (KALLSYMS off) are recorded raw
  with a note. Thin arch-specific layer for register/fault-line formats (arm64 `pc :`/`lr :` and
  "Unable to handle kernel …"; x86 `RIP:`/`RSP:` and "BUG: unable to handle page fault …").
- `crash/merge.py` — merge a `crash.gdb.json` live snapshot into the matching `CrashEvent` (adds
  `file:line`, live registers, exact backtrace).
- `crash/render.py` — `render_json(report) -> dict`, `render_markdown(report) -> str`.

(No `symbolize.py` in v1: symbolization is "read the KALLSYMS frames + graft gdb-live". `System.map`/
`addr2line` enrichment is a later module.)

### 4.3 Thin impure shell
- `crash/analyze.py` — `analyze_run(run_dir) -> CrashReport`: reads `console.raw` + optional
  `crash.gdb.json`, runs parse → merge → render, writes `crash.json` + `crash.md`, and updates
  `run.json` (crash summary block; status → `crashed` on a fatal event). Single entry point for both
  `--analyze-crash` and the `pane-died` hook.

### 4.4 Edits to existing modules (small, at established seams)
- `qemu.py` (`build_qemu_argv`) — replace bare `-nographic` with the explicit chardev/serial/display
  wiring above; thread the `console.raw` path in from the recorder/context.
- `launchers.py` — `qemu_container_command` adds an rw mount for the run's `logs/`; `gdb_pane_command`
  adds a narrow rw mount for `<run>/crash/`.
- `gdbcmd.py` — the embedded gdb-Python payload gains a self-contained `CrashCapture` breakpoint class;
  the crash symbol list + crash-drop path injected from config at arg-build time.
- `stages/debuggee.py` / `stages/debugger.py` — thread console path / crash-drop path + crash symbol
  list + `break_on_crash` flag.
- `run_artifacts.py` (`RunRecorder`) — expose `console_raw` and `crash_dir`; pre-create both in
  `start`; add `crashed` to the `RunStatus` literal; crash summary block + status flip in `analyze_run`.
- `config.py` — `[debuggee] capture_console`; `[debugger] break_on_crash` + `crash_breakpoints`.
- `cli.py` — `--analyze-crash [RUN-ID]` dispatch (Docker/tmux-free, like `--explain-config`).
- `.tmux.conf` — a `pane-died` hook running `start_kgdb --analyze-crash` (default `latest`).

## 5. Data flow (end to end)

1. `RunRecorder.start` pre-creates `logs/console.raw` and `crash/`.
2. Debuggee stage → QEMU tees console to the pane **and** byte-logs to `console.raw` (native: host
   path; in-container: run `logs/` mounted rw, identical path under the colima share).
3. Debugger stage → gdb attaches, installs `likedbg-reconnect` + `CrashCapture` breakpoints on the
   curated symbols, with `crash/` mounted rw.
4. **Crash** → a curated breakpoint hits → gdb halts (operator lands at the fault with registers)
   **and** `CrashCapture.stop()` writes `crash/crash.gdb.json`, prints a marker, returns `True`.
5. `analyze_run` (manual `--analyze-crash`, or the `pane-died` hook on QEMU exit) → parse `console.raw`
   → merge `crash.gdb.json` → write `crash.json` + `crash.md`, update `run.json` (+ `crashed` status
   on a fatal event).
6. `--analyze-crash [run-id]` re-runs step 5 on any saved run — pure host, no Docker/tmux, no
   `System.map` dependency.

## 6. `crash.json` schema + run status

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

`crash.md` renders the same object. `run.json` gains a `crash` summary block (primary class/title +
`crash.json`/`crash.md` pointers) and, on a fatal event, status `crashed` (see CONTEXT.md **Run
artifact**). `WARN`-only runs record the event but do not flip status.

## 7. Panic-break gdb integration

- Embedded payload gains `CrashCapture(gdb.Breakpoint)` installed on each configured crash symbol;
  each install wrapped so **missing symbols are tolerated** (no error when a build lacks KASAN/UBSAN).
- Default set is **arch-independent** (all symbols exist on both arches; `die` generalizes the
  arch-specific fatal-fault paths and carries `pt_regs`). Arch-specificity lives only in the *parser*.
- Runtime faults (MMU on) → plain software `break`; `hbreak` stays for early boot / `start_kernel`.
- `stop()` captures: stopped symbol, register set, gdb-symbolized `bt`, and — for `die` — the
  `pt_regs` argument (faulting context, with a `$pc`/`$sp` frame-register fallback); for
  `kasan_report` the access details it can read. Writes `crash/crash.gdb.json`, prints a one-line
  marker, returns `True` so gdb halts.

## 8. Config surface

- `[debuggee] capture_console = true` — the `logfile=` Console log sink (default on; harmless).
- `[debugger] break_on_crash = true` — install `CrashCapture` breakpoints (default on).
- `[debugger] crash_breakpoints = ["panic","die","oops_enter","kasan_report","ubsan_epilogue"]` —
  the lean arch-independent default, fully overridable.

Crash detection is **orthogonal to Debug profiles** by design: it lives on the existing QEMU-vs-gdb
axis (`[debuggee]` / `[debugger]`), and `[debugger]` deliberately does not participate in the profile
`effective_debuggee` re-merge (which is `[debuggee]`-only). The static, comprehensive, missing-tolerant
default set means no profile needs to inject `kasan_report`/`ubsan_epilogue`. This honors CONTEXT.md's
guidance that a Debug profile must not "silently override unrelated config."

## 9. CLI + teardown

- **`--analyze-crash [RUN-ID]`** — `nargs="?"`, `const="latest"`. Pure host, Docker/tmux-free: writes
  `crash.json`/`crash.md`, prints a short summary (class, title, primary faulting frame, paths).
  Re-runnable on any archived run. **Primary trigger** for the panic-break-trap workflow (you are
  already in gdb at the fault; run it from another pane).
- **Auto — a tmux `pane-died` hook in `.tmux.conf`** (where `C-b B` + `remain-on-exit` already live;
  runtime never mutates bindings — ADR-0005). Fires `start_kgdb --analyze-crash` when the Debuggee
  pane's process exits, covering the **QEMU-exit subset** (panic→reboot, or manual quit). The
  panic-break-trap case does not exit QEMU → stays manual, but `crash.gdb.json` is already on disk the
  instant the breakpoint hit. No shell append to a process pane, no cross-container shelling.

## 10. Error handling / edge cases

- No `console.raw` / empty / no crash signature → clean "no crash detected" (exit 0, no report file),
  never an error.
- Truncated crash block (rebooted mid-print) → best-effort parse; event flagged `incomplete`.
- `crash.gdb.json` absent (headless / `break_on_crash=false` / never trapped) → console-only report.
- Raw-hex frames (KALLSYMS off) → recorded raw + a note; the soft `CONFIG_KALLSYMS` expectation warns
  at build time.
- Missing gdb crash symbols → tolerated (§7).
- Panic action: default `panic = halt` (`panic=0`) with `oops=panic` upstream — the guest halts and
  `console.raw` holds the full dump; with gdb attached the crash breakpoint holds it before any reboot.
- The rw crash-drop dir is created by `RunRecorder.start` before the container launches.

## 11. Testing + live gate

- **Unit (bulk, deterministic, no Docker):** `parse_console` against captured real KALLSYMS-symbolic
  fixtures for every class × both arches (panic, oops/`BUG`, KASAN, UBSAN, x86 `#GP`, page-fault, arm64
  abort, WARN) + a raw-frame (KALLSYMS-off) fixture; `merge` of a `crash.gdb.json` fixture;
  `render_markdown` snapshot; `analyze_run` against a fixture run dir → merged `crash.json` +
  `run.json` `crashed` flip.
- **Unit (wiring):** qemu argv contains the explicit chardev `logfile=` (and no bare `-nographic`);
  container commands contain the rw mounts; gdb args contain the crash breakpoints from config; config
  knobs parse + default; the new soft `CONFIG_KALLSYMS` expectation resolves.
- **Live gate (both arches, per project discipline):** trigger real crashes —
  `echo c > /proc/sysrq-trigger` (panic), an in-tree `lib/test_kasan` UAF or a tiny null-deref module
  (oops) — and confirm: gdb halts at the fault with live registers, `console.raw` captured pure,
  `crash.json`/`crash.md` produced with a symbolized trace, `run.json` → `crashed`, `pane-died` hook
  fires on a reboot-crash. M5 (arm64) + Ubuntu VM / in-container (x86_64).

## 12. Risks / open items

- **`die` `pt_regs` extraction in gdb** across arches/inlining — mitigated by the `$pc`/`$sp`
  frame-register fallback (§7); validate at the live gate.
- **KASAN report shape** varies by kernel version; pin the 6.6.x format in fixtures and degrade
  gracefully on drift.
- **Console `logfile=` in-container path** — the run `logs/` dir must be writable by the in-container
  QEMU; confirm the mount + path identity under colima's share at the live gate (native is trivial).
- **Cache sensitivity:** enabling sanitizer profiles for the live gate forces kernel rebuilds
  (ADR-0003 content-hash); expected, not a regression.

## 13. Docs (done in this pass)

- **ADR-0007** — crash-capture console sink + KALLSYMS-not-System.map symbolization (created).
- **CONTEXT.md** — added **Console log** and **Crash report**; extended **Run artifact** status with
  `crashed`.

## 14. Grill resolutions (2026-07-04, grill-with-docs)

Six tension points found against the code/docs and resolved (all to the recommended option):

1. **Console sink wiring** — bare `-nographic` = muxed `-serial mon:stdio`; to add `logfile=` we define
   the chardev explicitly and **drop the stdio HMP monitor** so `console.raw` stays pure serial. → §3.1,
   ADR-0007.
2. **Symbolization source** — the kernel already symbolizes via `CONFIG_KALLSYMS` (base profile); and
   `System.map` is not host-visible in volume mode → **defer System.map**, lean on KALLSYMS + gdb-live,
   add a soft `CONFIG_KALLSYMS` expectation, degrade gracefully on raw frames. → §2/§3.3/§4.2, ADR-0007.
3. **Teardown trigger vs ADR-0005** — panes are process panes (no shell to append to) and panic-break
   keeps QEMU running → **manual `--analyze-crash` primary + a `.tmux.conf` `pane-died` hook** for the
   QEMU-exit subset. → §9.
4. **Run status** — the glossary reserves crash states for B3 → **add `crashed`**, set post-hoc by
   `analyze_run`; completion/exit states left to B5. → §6, CONTEXT.md.
5. **Breakpoint set** — the symbols are arch-independent (`die` generalizes fatal faults) → **lean list**
   `panic/die/oops_enter/kasan_report/ubsan_epilogue`; arch-specificity only in the parser. → §7.
6. **Config placement** — `capture_console` → `[debuggee]`, `break_on_crash`/`crash_breakpoints` →
   `[debugger]`; crash detection is **orthogonal to profiles** (static default, no profile re-merge). → §8.
