# Crash Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give LIKE-DBG a crash/oops detector that turns a Debuggee fault into a symbolized `crash.json`/`crash.md`, and make gdb halt at the fault with live state (panic-break).

**Architecture:** A dedicated byte-exact serial **Console log** (`logs/console.raw`, QEMU `-chardev … logfile=`) feeds a pure, I/O-free `crash/` parser core (`parse → merge → render`); gdb-side `CrashCapture` breakpoints dump live state to `crash/crash.gdb.json` via a narrow rw mount; a thin `analyze_run` shell merges the two into the report and flips run status to `crashed`. Exposed on-demand as `--analyze-crash [run-id]` (pure host) plus a `.tmux.conf` `pane-died` hook.

**Tech Stack:** Python 3.12, Pydantic v2 (frozen models), loguru, `gdb` Python API (embedded self-contained payload), QEMU chardev, tmux, pytest, ruff, mypy `--strict`, uv.

## Global Constraints

- **dev stays local — never `git push`.** Work on branch `feat/crash-intel` off `dev`; merge locally at the end.
- Python **3.12**; all new code passes `uv run ruff check`, `uv run ruff format --check`, `uv run mypy src` (strict), `uv run pytest -q`.
- Pydantic config models are `frozen=True, extra="forbid"` (`_Base`). New config keys need matching `configs/default.toml` entries.
- The `crash/` core is **I/O-free** (no file/Docker/tmux access) except `crash/analyze.py`, the single impure shell.
- gdb-side capture is **self-contained embedded Python** — the `likedbg` package is NOT importable inside the debugger container. Mirror the existing `_reconnect_helper` string-payload pattern in `gdbcmd.py`.
- Symbolization leans on the kernel's `CONFIG_KALLSYMS` output + gdb-live; **no `System.map`/`addr2line`** in this branch (ADR-0007). Raw-hex frames are recorded raw with a note, never faked.
- JSON key is `"class"`; the Python dataclass field is `kind` (`class` is a keyword). `render_json` maps `kind → "class"`.
- Crash-only breakpoints default: `["panic", "die", "oops_enter", "kasan_report", "ubsan_epilogue"]`. Missing symbols are tolerated (never raise).
- Spec: `docs/superpowers/specs/2026-07-04-crash-intel-design.md`. Decisions: ADR-0007. Glossary: CONTEXT.md (**Console log**, **Crash report**, **Run artifact** `crashed`).

---

## File Structure

**New (`crash/` pure core + shell):**
- `src/likedbg/crash/__init__.py` — public API re-exports
- `src/likedbg/crash/model.py` — `Frame`, `KasanInfo`, `GdbLive`, `CrashEvent`, `CrashReport` (+ `to_dict`)
- `src/likedbg/crash/parse.py` — `normalize`, `parse_console`
- `src/likedbg/crash/merge.py` — `merge_gdb_live`
- `src/likedbg/crash/render.py` — `render_json`, `render_markdown`
- `src/likedbg/crash/analyze.py` — `analyze_run` (the only impure module)
- `tests/test_crash_model.py`, `tests/test_crash_parse.py`, `tests/test_crash_merge.py`, `tests/test_crash_render.py`, `tests/test_crash_analyze.py`
- `tests/fixtures/crash/*.txt` — captured console fixtures

**Modified:**
- `src/likedbg/constants.py` — `CRASH_DROP_MOUNT`
- `src/likedbg/config.py`, `configs/default.toml` — `capture_console`, `break_on_crash`, `crash_breakpoints`
- `src/likedbg/qemu.py` — `build_qemu_argv(… console_log=)`
- `src/likedbg/launchers.py` — `qemu_container_command(… extra_rw_dirs=)`, `gdb_pane_command(… crash_drop=)`
- `src/likedbg/gdbcmd.py` — `CrashCapture` payload + `build_gdb_args(… break_on_crash=, crash_breakpoints=, crash_drop_path=)`
- `src/likedbg/run_artifacts.py` — `console_raw`, `crash_dir`, `crash/` subdir, `RunStatus += "crashed"`
- `src/likedbg/stages/debuggee.py`, `src/likedbg/stages/debugger.py` — thread the new params
- `src/likedbg/cli.py` — pipeline wiring + `--analyze-crash`
- `configs/profiles/{exploit-dev,crash-debug,kasan,ubsan}.toml` — soft `CONFIG_KALLSYMS`
- `.tmux.conf` — `pane-died` hook
- `docs/superpowers/ROADMAP.md` — mark B3 done at the end

**Branch setup (before Task 1):**
```bash
git checkout dev && git checkout -b feat/crash-intel
```

---

## Task 1: Crash model

**Files:**
- Create: `src/likedbg/crash/__init__.py`, `src/likedbg/crash/model.py`
- Test: `tests/test_crash_model.py`

**Interfaces:**
- Produces: `Frame(raw, symbol, offset, module=None, file=None, line=None)`; `KasanInfo(access, size, bad_addr)`; `GdbLive(stopped_at, registers, backtrace)`; `CrashEvent(kind, fatal, title, message_lines=[], fault_addr=None, fault_pc=None, registers={}, trace=[], kasan=None, gdb_live=None, incomplete=False, source=["console"])`; `CrashReport(arch, build_label, kernel_release, events, primary, generated_at=None, schema_version=1)`. `CrashReport.to_dict()` and `CrashEvent.to_dict()` return JSON-ready dicts with the `kind → "class"` rename and a derived top-level `sources` list.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crash_model.py
from likedbg.crash.model import CrashEvent, CrashReport, Frame, GdbLive


def test_event_to_dict_renames_kind_to_class():
    ev = CrashEvent(kind="kasan", fatal=True, title="use-after-free")
    d = ev.to_dict()
    assert d["class"] == "kasan"
    assert "kind" not in d
    assert d["fatal"] is True and d["source"] == ["console"]


def test_report_to_dict_derives_sources_and_primary():
    ev = CrashEvent(
        kind="oops", fatal=True, title="BUG", trace=[Frame(raw="a+0x1/0x2", symbol="a", offset=1)],
        gdb_live=GdbLive(stopped_at="die", registers={"pc": "0x1"}, backtrace=["#0 die"]),
        source=["console", "gdb-live"],
    )
    rep = CrashReport(arch="x86_64", build_label="linux-6.6.30-x", kernel_release="6.6.30", events=[ev], primary=0)
    d = rep.to_dict()
    assert d["schema_version"] == 1 and d["primary"] == 0
    assert d["sources"] == ["console", "gdb-live"]
    assert d["events"][0]["gdb_live"]["stopped_at"] == "die"
    assert d["events"][0]["trace"][0]["symbol"] == "a"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_model.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'likedbg.crash'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/likedbg/crash/__init__.py
"""Crash intelligence: pure parse/merge/render core + the analyze_run shell."""

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport
from likedbg.crash.model import Frame
from likedbg.crash.model import GdbLive
from likedbg.crash.model import KasanInfo

__all__ = ["CrashEvent", "CrashReport", "Frame", "GdbLive", "KasanInfo"]
```

```python
# src/likedbg/crash/model.py
"""Crash report data model. Pure dataclasses; JSON key `class` maps to the `kind` field."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass(frozen=True)
class Frame:
    raw: str
    symbol: str | None
    offset: int | None
    module: str | None = None
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "symbol": self.symbol,
            "offset": self.offset,
            "module": self.module,
            "file": self.file,
            "line": self.line,
        }


@dataclass(frozen=True)
class KasanInfo:
    access: str | None
    size: int | None
    bad_addr: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.access, "size": self.size, "bad_addr": self.bad_addr}


@dataclass(frozen=True)
class GdbLive:
    stopped_at: str
    registers: dict[str, str]
    backtrace: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"stopped_at": self.stopped_at, "registers": dict(self.registers), "backtrace": list(self.backtrace)}


@dataclass
class CrashEvent:
    kind: str
    fatal: bool
    title: str
    message_lines: list[str] = field(default_factory=list)
    fault_addr: str | None = None
    fault_pc: Frame | None = None
    registers: dict[str, str] = field(default_factory=dict)
    trace: list[Frame] = field(default_factory=list)
    kasan: KasanInfo | None = None
    gdb_live: GdbLive | None = None
    incomplete: bool = False
    source: list[str] = field(default_factory=lambda: ["console"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.kind,
            "fatal": self.fatal,
            "incomplete": self.incomplete,
            "title": self.title,
            "fault_addr": self.fault_addr,
            "fault_pc": self.fault_pc.to_dict() if self.fault_pc else None,
            "access": self.kasan.to_dict() if self.kasan else None,
            "registers": dict(self.registers),
            "trace": [f.to_dict() for f in self.trace],
            "gdb_live": self.gdb_live.to_dict() if self.gdb_live else None,
            "source": list(self.source),
        }


@dataclass
class CrashReport:
    arch: str
    build_label: str
    kernel_release: str | None
    events: list[CrashEvent]
    primary: int | None
    generated_at: str | None = None
    schema_version: int = 1

    def sources(self) -> list[str]:
        seen: list[str] = []
        for ev in self.events:
            for s in ev.source:
                if s not in seen:
                    seen.append(s)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "arch": self.arch,
            "build_label": self.build_label,
            "kernel_release": self.kernel_release,
            "generated_at": self.generated_at,
            "sources": self.sources(),
            "primary": self.primary,
            "events": [e.to_dict() for e in self.events],
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_crash_model.py -q && uv run mypy src/likedbg/crash`
Expected: PASS; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/crash/__init__.py src/likedbg/crash/model.py tests/test_crash_model.py
git commit -m "feat(crash): crash report data model"
```

---

## Task 2: Console parser — scaffold + panic/oops + call-trace

**Files:**
- Create: `src/likedbg/crash/parse.py`, `tests/test_crash_parse.py`
- Create: `tests/fixtures/crash/x86_oops.txt`, `tests/fixtures/crash/arm64_oops.txt`, `tests/fixtures/crash/panic.txt`

**Interfaces:**
- Consumes: `CrashEvent`, `Frame` (Task 1).
- Produces: `normalize(text: str) -> str` (CRLF→LF, strips lone `\r`); `parse_console(text: str, arch: str) -> list[CrashEvent]`. Each detected fault is one `CrashEvent`; `trace` holds symbolic frames the kernel printed (`func+off/size`), raw hex kept when non-symbolic.

- [ ] **Step 1: Create fixtures**

`tests/fixtures/crash/x86_oops.txt` (note the CRLF — real tty capture; store literally):
```
[   12.345678] BUG: kernel NULL pointer dereference, address: 0000000000000000
[   12.345680] #PF: supervisor read access in kernel mode
[   12.345681] Oops: 0000 [#1] PREEMPT SMP NOPTI
[   12.345683] CPU: 0 PID: 141 Comm: poc Not tainted 6.6.30 #1
[   12.345685] RIP: 0010:vuln_read+0x1a/0x40
[   12.345687] RSP: 0018:ffffc90000abfe10 EFLAGS: 00010246
[   12.345689] RAX: 0000000000000000 RBX: ffff8880069b8000 RCX: 0000000000000000
[   12.345693] Call Trace:
[   12.345694]  <TASK>
[   12.345695]  vuln_ioctl+0x33/0x60
[   12.345697]  __x64_sys_ioctl+0x90/0xd0
[   12.345699]  do_syscall_64+0x5c/0x90
```

`tests/fixtures/crash/arm64_oops.txt`:
```
[    9.100000] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[    9.100050] Mem abort info:
[    9.100200] CPU: 0 PID: 130 Comm: poc Not tainted 6.6.30 #1
[    9.100260] pc : vuln_read+0x1c/0x48
[    9.100262] lr : vuln_ioctl+0x30/0x60
[    9.100265] sp : ffff800008abbd60
[    9.100290] Call trace:
[    9.100292]  vuln_read+0x1c/0x48
[    9.100294]  vuln_ioctl+0x30/0x60
[    9.100296]  __arm64_sys_ioctl+0x54/0x90
```

`tests/fixtures/crash/panic.txt`:
```
[   20.000000] Kernel panic - not syncing: sysrq triggered crash
[   20.000010] CPU: 1 PID: 200 Comm: bash Not tainted 6.6.30 #1
[   20.000020] Call Trace:
[   20.000021]  panic+0x120/0x2c0
[   20.000023]  sysrq_handle_crash+0x18/0x20
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_crash_parse.py
from pathlib import Path

from likedbg.crash.parse import normalize, parse_console

FIX = Path(__file__).parent / "fixtures" / "crash"


def _read(name: str) -> str:
    return (FIX / name).read_text()


def test_normalize_strips_crlf():
    assert normalize("a\r\nb\rc\n") == "a\nb\nc\n"


def test_x86_oops_classified_with_rip_and_trace():
    events = parse_console(_read("x86_oops.txt"), "x86_64")
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "oops" and ev.fatal is True
    assert ev.fault_pc is not None and ev.fault_pc.symbol == "vuln_read"
    assert ev.fault_addr == "0000000000000000"
    assert [f.symbol for f in ev.trace] == ["vuln_ioctl", "__x64_sys_ioctl", "do_syscall_64"]
    assert ev.registers.get("RSP", "").startswith("0018:")


def test_arm64_oops_uses_pc_line_and_call_trace():
    events = parse_console(_read("arm64_oops.txt"), "arm64")
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "oops"
    assert ev.fault_pc is not None and ev.fault_pc.symbol == "vuln_read"
    assert [f.symbol for f in ev.trace][:2] == ["vuln_read", "vuln_ioctl"]


def test_panic_detected():
    events = parse_console(_read("panic.txt"), "x86_64")
    assert len(events) == 1 and events[0].kind == "panic" and events[0].fatal is True
    assert "sysrq triggered crash" in events[0].title
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_parse.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'likedbg.crash.parse'`.

- [ ] **Step 4: Write minimal implementation**

```python
# src/likedbg/crash/parse.py
"""Parse a raw serial Console log into CrashEvents. Arch-shared scaffold + thin
arch-specific register/fault-line handling. Frames are taken as the kernel symbolized
them (CONFIG_KALLSYMS); raw-hex frames are kept raw. No System.map (ADR-0007)."""

from __future__ import annotations

import re

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import Frame

# Strip the leading "[   12.345678] " dmesg timestamp so patterns match the message.
_TS = re.compile(r"^\[\s*\d+\.\d+\]\s?")
# A printed call-trace frame: "func+0x1a/0x40" optionally "[module]".
_FRAME = re.compile(r"^([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+(?:\s+\[(\w+)\])?$")
_X86_RIP = re.compile(r"^RIP:\s*[0-9a-fA-F]+:([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+")
_X86_REG = re.compile(r"^(R[A-Z0-9]{2}|RIP|RSP|EFLAGS):")
_ARM_PC = re.compile(r"^pc :\s*([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+")
_ARM_REG = re.compile(r"^(pc|lr|sp|x\d+) :")


def normalize(text: str) -> str:
    """CRLF/lone-CR → LF (tty capture carries \\r\\n; see the B1 .config CRLF fix)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _strip(line: str) -> str:
    return _TS.sub("", line).rstrip()


def _frame(line: str) -> Frame | None:
    body = _strip(line).strip()
    m = _FRAME.match(body)
    if m:
        return Frame(raw=body, symbol=m.group(1), offset=int(m.group(2), 16), module=m.group(3))
    return None


# Fault-onset markers → (kind, fatal). Order matters: first match on a line wins.
_ONSET: list[tuple[re.Pattern[str], str, bool]] = [
    (re.compile(r"^Kernel panic - not syncing:\s*(?P<msg>.*)"), "panic", True),
    (re.compile(r"^BUG: KASAN:"), "kasan", True),
    (re.compile(r"^(?:BUG: )?unable to handle kernel|^BUG: kernel NULL pointer"), "oops", True),
    (re.compile(r"^Unable to handle kernel"), "oops", True),
    (re.compile(r"^Oops:\s"), "oops", True),
]


def parse_console(text: str, arch: str) -> list[CrashEvent]:
    lines = normalize(text).splitlines()
    events: list[CrashEvent] = []
    cur: CrashEvent | None = None
    in_trace = False
    for raw_line in lines:
        body = _strip(raw_line)
        # New fault onset?
        onset = _classify(body)
        if onset is not None:
            kind, fatal, title = onset
            cur = CrashEvent(kind=kind, fatal=fatal, title=title, message_lines=[body])
            events.append(cur)
            in_trace = False
            _maybe_fault_addr(cur, body)
            continue
        if cur is None:
            continue
        cur.message_lines.append(body)
        # Trace start markers.
        if body.startswith(("Call Trace:", "Call trace:")):
            in_trace = True
            continue
        # Registers / fault PC (arch-specific).
        if arch == "x86_64":
            _x86_line(cur, body)
        else:
            _arm_line(cur, body)
        # Frames inside the trace.
        if in_trace:
            fr = _frame(raw_line)
            if fr is not None:
                cur.trace.append(fr)
    return events


def _classify(body: str) -> tuple[str, bool, str] | None:
    for pat, kind, fatal in _ONSET:
        m = pat.match(body)
        if m:
            title = m.groupdict().get("msg") or body
            return kind, fatal, title.strip()
    return None


def _maybe_fault_addr(ev: CrashEvent, body: str) -> None:
    m = re.search(r"address:?\s*([0-9a-fA-Fx]+)", body)
    if m:
        ev.fault_addr = m.group(1).removeprefix("0x")


def _x86_line(ev: CrashEvent, body: str) -> None:
    m = _X86_RIP.match(body)
    if m:
        ev.fault_pc = Frame(raw=body, symbol=m.group(1), offset=int(m.group(2), 16))
    if _X86_REG.match(body):
        for key, val in re.findall(r"([A-Z]{2,7}):\s*(\S+)", body):
            ev.registers[key] = val


def _arm_line(ev: CrashEvent, body: str) -> None:
    m = _ARM_PC.match(body)
    if m:
        ev.fault_pc = Frame(raw=body, symbol=m.group(1), offset=int(m.group(2), 16))
    if _ARM_REG.match(body):
        for key, val in re.findall(r"(pc|lr|sp|x\d+) :\s*(\S+)", body):
            ev.registers[key] = val
```

- [ ] **Step 5: Run tests + commit**

Run: `uv run pytest tests/test_crash_parse.py -q && uv run mypy src/likedbg/crash/parse.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/crash/parse.py tests/test_crash_parse.py tests/fixtures/crash/
git commit -m "feat(crash): parse panic/oops + call-trace (x86_64 + arm64)"
```

---

## Task 3: Console parser — KASAN / UBSAN / WARN / incomplete

**Files:**
- Modify: `src/likedbg/crash/parse.py`
- Modify: `tests/test_crash_parse.py`
- Create: `tests/fixtures/crash/kasan_uaf.txt`, `tests/fixtures/crash/ubsan.txt`, `tests/fixtures/crash/warn.txt`, `tests/fixtures/crash/truncated.txt`

**Interfaces:**
- Consumes: `KasanInfo` (Task 1), the Task 2 parser.
- Produces: KASAN events carry `kasan: KasanInfo`; `warn` events are `fatal=False`; a fault whose trace/registers never close before EOF or a reboot marker is flagged `incomplete=True`.

- [ ] **Step 1: Create fixtures**

`tests/fixtures/crash/kasan_uaf.txt`:
```
[   15.100000] ==================================================================
[   15.100002] BUG: KASAN: use-after-free in kfree_test+0x120/0x180
[   15.100004] Read of size 8 at addr ffff88800a1b2c00 by task poc/151
[   15.100010] CPU: 0 PID: 151 Comm: poc Not tainted 6.6.30 #1
[   15.100020] Call Trace:
[   15.100021]  <TASK>
[   15.100022]  kfree_test+0x120/0x180
[   15.100024]  vuln_ioctl+0x40/0x70
[   15.100030] ==================================================================
```

`tests/fixtures/crash/ubsan.txt`:
```
[   16.200000] ================================================================================
[   16.200002] UBSAN: array-index-out-of-bounds in drivers/vuln/vuln.c:42:9
[   16.200004] index 16 is out of range for type 'int [16]'
[   16.200010] Call Trace:
[   16.200011]  vuln_write+0x88/0x120
[   16.200013] ================================================================================
```

`tests/fixtures/crash/warn.txt`:
```
[   17.300000] ------------[ cut here ]------------
[   17.300002] WARNING: CPU: 0 PID: 1 at kernel/sched/core.c:123 __schedule+0x5a0/0x600
[   17.300010] Call Trace:
[   17.300011]  __schedule+0x5a0/0x600
[   17.300013]  schedule+0x40/0xb0
```

`tests/fixtures/crash/truncated.txt` (oops cut off mid-trace by a reboot):
```
[   18.400000] BUG: kernel NULL pointer dereference, address: 0000000000000000
[   18.400010] RIP: 0010:vuln_read+0x1a/0x40
[   18.400020] Call Trace:
[   18.400021]  vuln_ioctl+0x33/0x60
[   18.400022] Rebooting in 1 seconds..
```

- [ ] **Step 2: Write the failing test**

```python
# add to tests/test_crash_parse.py
from likedbg.crash.parse import parse_console  # already imported


def test_kasan_access_details():
    ev = parse_console(_read("kasan_uaf.txt"), "x86_64")[0]
    assert ev.kind == "kasan" and ev.fatal is True
    assert ev.kasan is not None
    assert ev.kasan.access == "read" and ev.kasan.size == 8
    assert ev.kasan.bad_addr == "ffff88800a1b2c00"
    assert "use-after-free" in ev.title
    assert [f.symbol for f in ev.trace] == ["kfree_test", "vuln_ioctl"]


def test_ubsan_detected():
    ev = parse_console(_read("ubsan.txt"), "x86_64")[0]
    assert ev.kind == "ubsan" and ev.fatal is True
    assert "array-index-out-of-bounds" in ev.title


def test_warn_is_nonfatal():
    ev = parse_console(_read("warn.txt"), "x86_64")[0]
    assert ev.kind == "warn" and ev.fatal is False


def test_truncated_flagged_incomplete():
    ev = parse_console(_read("truncated.txt"), "x86_64")[0]
    assert ev.incomplete is True
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_parse.py -q`
Expected: FAIL — KASAN/UBSAN/WARN not classified; `kasan` is None.

- [ ] **Step 4: Extend the parser**

In `parse.py`, import `KasanInfo` and extend the onset table + add KASAN/UBSAN/WARN handling and the incomplete flag:

```python
from likedbg.crash.model import KasanInfo  # add to imports

# extend _ONSET (insert UBSAN + WARN; KASAN already present from Task 2):
_ONSET += [
    (re.compile(r"^UBSAN:\s*(?P<msg>.*)"), "ubsan", True),
    (re.compile(r"^WARNING: CPU:.*at .*\s(?P<msg>\S+\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)"), "warn", False),
]

_KASAN_ACCESS = re.compile(r"(Read|Write) of size (\d+) at addr ([0-9a-fA-F]+)")
_REBOOT = re.compile(r"Rebooting in |Kernel Offset: |---\[ end Kernel panic")
```

Update `_classify` so the KASAN title keeps the descriptive text:

```python
def _classify(body: str) -> tuple[str, bool, str] | None:
    for pat, kind, fatal in _ONSET:
        m = pat.match(body)
        if m:
            title = m.groupdict().get("msg") or body
            return kind, fatal, title.strip()
    return None
```

Add KASAN access extraction + incomplete detection inside the `parse_console` loop, right after `cur.message_lines.append(body)`:

```python
        if cur.kind == "kasan":
            km = _KASAN_ACCESS.search(body)
            if km:
                cur.kasan = KasanInfo(access=km.group(1).lower(), size=int(km.group(2)), bad_addr=km.group(3))
        if _REBOOT.search(body) and cur is not None:
            cur.incomplete = True
```

Finally, after the loop, mark any event that opened a trace but never saw a closing marker/EOF cleanly as incomplete is already covered by the reboot marker; also flag a KASAN event with no closing `====` line:

```python
    for ev in events:
        if ev.kind == "kasan" and not any(set(line) == {"="} for line in ev.message_lines[1:]):
            ev.incomplete = True
    return events
```

(Replace the existing `return events` with the block above.)

- [ ] **Step 5: Run tests + commit**

Run: `uv run pytest tests/test_crash_parse.py -q && uv run mypy src/likedbg/crash/parse.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/crash/parse.py tests/test_crash_parse.py tests/fixtures/crash/
git commit -m "feat(crash): parse KASAN/UBSAN/WARN + incomplete flag"
```

---

## Task 4: gdb-live merge

**Files:**
- Create: `src/likedbg/crash/merge.py`, `tests/test_crash_merge.py`

**Interfaces:**
- Consumes: `CrashEvent`, `GdbLive` (Task 1).
- Produces: `merge_gdb_live(events: list[CrashEvent], gdb_live: dict[str, Any]) -> list[CrashEvent]`. Attaches the live snapshot to the **primary** (first fatal, else first) event, sets `gdb_live` and appends `"gdb-live"` to that event's `source`. A falsy/malformed `gdb_live` dict is a no-op.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crash_merge.py
from likedbg.crash.merge import merge_gdb_live
from likedbg.crash.model import CrashEvent


def _events():
    return [
        CrashEvent(kind="warn", fatal=False, title="w"),
        CrashEvent(kind="oops", fatal=True, title="o"),
    ]


def test_merge_attaches_to_first_fatal():
    gl = {"stopped_at": "die", "registers": {"pc": "0x1"}, "backtrace": ["#0 die", "#1 vuln"]}
    out = merge_gdb_live(_events(), gl)
    assert out[1].gdb_live is not None and out[1].gdb_live.stopped_at == "die"
    assert out[1].source == ["console", "gdb-live"]
    assert out[0].gdb_live is None


def test_merge_empty_is_noop():
    out = merge_gdb_live(_events(), {})
    assert all(e.gdb_live is None for e in out)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_merge.py -q`
Expected: FAIL — no module `likedbg.crash.merge`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/likedbg/crash/merge.py
"""Merge a gdb-live crash snapshot (crash.gdb.json) into the primary CrashEvent."""

from __future__ import annotations

from typing import Any

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import GdbLive


def _primary_index(events: list[CrashEvent]) -> int | None:
    if not events:
        return None
    for i, ev in enumerate(events):
        if ev.fatal:
            return i
    return 0


def merge_gdb_live(events: list[CrashEvent], gdb_live: dict[str, Any]) -> list[CrashEvent]:
    idx = _primary_index(events)
    if idx is None or not gdb_live or "stopped_at" not in gdb_live:
        return events
    ev = events[idx]
    ev.gdb_live = GdbLive(
        stopped_at=str(gdb_live.get("stopped_at", "")),
        registers={str(k): str(v) for k, v in dict(gdb_live.get("registers", {})).items()},
        backtrace=[str(x) for x in gdb_live.get("backtrace", [])],
    )
    if "gdb-live" not in ev.source:
        ev.source.append("gdb-live")
    return events
```

- [ ] **Step 4: Run test + commit**

Run: `uv run pytest tests/test_crash_merge.py -q && uv run mypy src/likedbg/crash/merge.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/crash/merge.py tests/test_crash_merge.py
git commit -m "feat(crash): merge gdb-live snapshot into primary event"
```

---

## Task 5: Render (json + markdown)

**Files:**
- Create: `src/likedbg/crash/render.py`, `tests/test_crash_render.py`

**Interfaces:**
- Consumes: `CrashReport` (Task 1).
- Produces: `render_json(report: CrashReport) -> dict[str, Any]` (== `report.to_dict()`); `render_markdown(report: CrashReport) -> str` — a human/blog-ready report: heading with arch + kernel_release, a section per event (class, title, faulting frame, KASAN access, registers, symbolized trace, gdb-live backtrace).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crash_render.py
from likedbg.crash.model import CrashEvent, CrashReport, Frame, KasanInfo
from likedbg.crash.render import render_json, render_markdown


def _report():
    ev = CrashEvent(
        kind="kasan", fatal=True, title="BUG: KASAN: use-after-free in kfree_test+0x120/0x180",
        kasan=KasanInfo(access="read", size=8, bad_addr="ffff88800a1b2c00"),
        fault_pc=Frame(raw="kfree_test+0x120/0x180", symbol="kfree_test", offset=288),
        trace=[Frame(raw="vuln_ioctl+0x40/0x70", symbol="vuln_ioctl", offset=64)],
        source=["console"],
    )
    return CrashReport(arch="x86_64", build_label="linux-6.6.30-x", kernel_release="6.6.30", events=[ev], primary=0)


def test_render_json_matches_to_dict():
    rep = _report()
    assert render_json(rep) == rep.to_dict()


def test_render_markdown_has_key_sections():
    md = render_markdown(_report())
    assert "# Crash report" in md
    assert "use-after-free" in md
    assert "kfree_test" in md
    assert "read" in md and "ffff88800a1b2c00" in md
    assert "vuln_ioctl" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_render.py -q`
Expected: FAIL — no module `likedbg.crash.render`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/likedbg/crash/render.py
"""Render a CrashReport as JSON (dict) and blog-ready Markdown."""

from __future__ import annotations

from typing import Any

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport


def render_json(report: CrashReport) -> dict[str, Any]:
    return report.to_dict()


def _frame_line(f: Any) -> str:
    loc = f" ({f.file}:{f.line})" if f.file else ""
    mod = f" [{f.module}]" if f.module else ""
    return f"`{f.raw}`{mod}{loc}"


def _event_md(i: int, ev: CrashEvent, primary: int | None) -> list[str]:
    star = " (primary)" if i == primary else ""
    out = [f"## Event {i}: {ev.kind}{star}", "", f"**{ev.title}**", ""]
    if ev.incomplete:
        out += ["> ⚠ capture incomplete (guest rebooted mid-dump)", ""]
    if ev.fault_pc:
        out += [f"- Faulting PC: {_frame_line(ev.fault_pc)}"]
    if ev.fault_addr:
        out += [f"- Fault address: `{ev.fault_addr}`"]
    if ev.kasan:
        out += [f"- KASAN: {ev.kasan.access} of size {ev.kasan.size} at `{ev.kasan.bad_addr}`"]
    if ev.registers:
        regs = " ".join(f"{k}={v}" for k, v in ev.registers.items())
        out += ["", "**Registers**", "", f"```\n{regs}\n```"]
    if ev.trace:
        out += ["", "**Call trace**", ""]
        out += [f"{n}. {_frame_line(f)}" for n, f in enumerate(ev.trace)]
    if ev.gdb_live:
        out += ["", f"**gdb-live @ {ev.gdb_live.stopped_at}**", "", "```"]
        out += list(ev.gdb_live.backtrace)
        out += ["```"]
    out += [""]
    return out


def render_markdown(report: CrashReport) -> str:
    head = [
        "# Crash report",
        "",
        f"- Build: `{report.build_label}` ({report.arch}, {report.kernel_release or 'unknown'})",
        f"- Sources: {', '.join(report.sources()) or 'none'}",
        f"- Events: {len(report.events)}",
        "",
    ]
    body: list[str] = []
    for i, ev in enumerate(report.events):
        body += _event_md(i, ev, report.primary)
    return "\n".join(head + body).rstrip() + "\n"
```

- [ ] **Step 4: Run test + commit**

Run: `uv run pytest tests/test_crash_render.py -q && uv run mypy src/likedbg/crash/render.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/crash/render.py tests/test_crash_render.py
git commit -m "feat(crash): render crash report as json + markdown"
```

---

## Task 6: `analyze_run` shell + `CrashError`

**Files:**
- Create: `src/likedbg/crash/analyze.py`, `tests/test_crash_analyze.py`
- Modify: `src/likedbg/errors.py`

**Interfaces:**
- Consumes: `parse_console` (T2/3), `merge_gdb_live` (T4), `render_json`/`render_markdown` (T5), `CrashReport` (T1).
- Produces: `analyze_run(run_dir: Path) -> CrashReport | None`. Reads `logs/console.raw`, optional `crash/crash.gdb.json`, `host.json` (`target_arch`), `run.json` (`build_label`; `kernel_release` derived from the label). Writes `crash.json` + `crash.md`; on a fatal event patches `run.json` status → `crashed` and adds a `crash` summary block. Returns `None` when there is no crash (writes nothing). `CrashError(LikeDbgError)` for a missing/invalid run dir.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crash_analyze.py
import json
from pathlib import Path

import pytest

from likedbg.crash.analyze import analyze_run
from likedbg.errors import CrashError


def _mkrun(tmp_path: Path, console: str, *, gdb: dict | None = None, arch: str = "x86_64") -> Path:
    run = tmp_path / "runs" / "r1"
    (run / "logs").mkdir(parents=True)
    (run / "crash").mkdir()
    (run / "logs" / "console.raw").write_text(console)
    (run / "host.json").write_text(json.dumps({"target_arch": arch}))
    (run / "run.json").write_text(json.dumps({"status": "launched", "build_label": "linux-6.6.30-x", "status_history": []}))
    if gdb is not None:
        (run / "crash" / "crash.gdb.json").write_text(json.dumps(gdb))
    return run


PANIC = "[ 1.0] Kernel panic - not syncing: test\n[ 1.0] Call Trace:\n[ 1.0]  panic+0x1/0x2\n"


def test_analyze_writes_report_and_flips_status(tmp_path):
    run = _mkrun(tmp_path, PANIC, gdb={"stopped_at": "panic", "registers": {}, "backtrace": ["#0 panic"]})
    rep = analyze_run(run)
    assert rep is not None and rep.events[0].kind == "panic"
    cj = json.loads((run / "crash.json").read_text())
    assert cj["arch"] == "x86_64" and cj["kernel_release"] == "6.6.30"
    assert cj["events"][0]["gdb_live"]["stopped_at"] == "panic"
    assert (run / "crash.md").is_file()
    rj = json.loads((run / "run.json").read_text())
    assert rj["status"] == "crashed" and rj["crash"]["primary_class"] == "panic"


def test_analyze_no_crash_returns_none(tmp_path):
    run = _mkrun(tmp_path, "[ 0.1] Booting Linux\n[ 0.2] systemd started\n")
    assert analyze_run(run) is None
    assert not (run / "crash.json").exists()


def test_analyze_missing_run_dir_raises(tmp_path):
    with pytest.raises(CrashError):
        analyze_run(tmp_path / "nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_crash_analyze.py -q`
Expected: FAIL — no module `likedbg.crash.analyze`.

- [ ] **Step 3: Add `CrashError`, then implement `analyze_run`**

Append to `src/likedbg/errors.py` (follow the existing subclass pattern):

```python
class CrashError(LikeDbgError):
    """Crash analysis could not run (missing/invalid run dir)."""
```

```python
# src/likedbg/crash/analyze.py
"""The single impure crash module: read a run dir, produce crash.json + crash.md,
flip run.json to `crashed`. Pure-host, Docker/tmux-free (ADR-0007)."""

from __future__ import annotations

import json
import re
from datetime import UTC
from datetime import datetime
from pathlib import Path

from likedbg.crash.merge import merge_gdb_live
from likedbg.crash.model import CrashReport
from likedbg.crash.parse import parse_console
from likedbg.crash.render import render_json
from likedbg.crash.render import render_markdown
from likedbg.errors import CrashError

_RELEASE = re.compile(r"linux-(\d+\.\d+(?:\.\d+)?)")


def _kernel_release(build_label: str) -> str | None:
    m = _RELEASE.search(build_label)
    return m.group(1) if m else None


def _primary_index(events: list) -> int | None:
    for i, ev in enumerate(events):
        if ev.fatal:
            return i
    return 0 if events else None


def analyze_run(run_dir: Path) -> CrashReport | None:
    if not run_dir.is_dir():
        raise CrashError(f"run dir not found: {run_dir}", remedy="pass a valid run-id or `latest`")
    console = run_dir / "logs" / "console.raw"
    if not console.is_file():
        raise CrashError(f"no console log at {console}", remedy="this run predates crash capture or never booted")
    host = json.loads((run_dir / "host.json").read_text())
    arch = str(host.get("target_arch", "x86_64"))
    run_json_path = run_dir / "run.json"
    run_json = json.loads(run_json_path.read_text())
    build_label = str(run_json.get("build_label", ""))

    events = parse_console(console.read_text(), arch)
    if not events:
        return None
    gdb_path = run_dir / "crash" / "crash.gdb.json"
    if gdb_path.is_file():
        try:
            events = merge_gdb_live(events, json.loads(gdb_path.read_text()))
        except json.JSONDecodeError:
            pass

    primary = _primary_index(events)
    report = CrashReport(
        arch=arch,
        build_label=build_label,
        kernel_release=_kernel_release(build_label),
        events=events,
        primary=primary,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    (run_dir / "crash.json").write_text(json.dumps(render_json(report), indent=2, sort_keys=True))
    (run_dir / "crash.md").write_text(render_markdown(report))

    prim = events[primary] if primary is not None else None
    if prim is not None and prim.fatal:
        run_json["status"] = "crashed"
        run_json.setdefault("status_history", []).append(
            {"status": "crashed", "at": report.generated_at, "message": prim.title}
        )
    run_json["crash"] = {
        "primary_class": prim.kind if prim else None,
        "title": prim.title if prim else None,
        "events": len(events),
        "report_json": "crash.json",
        "report_md": "crash.md",
    }
    run_json_path.write_text(json.dumps(run_json, indent=2, sort_keys=True))
    return report
```

- [ ] **Step 4: Run test + commit**

Run: `uv run pytest tests/test_crash_analyze.py -q && uv run mypy src/likedbg/crash`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/crash/analyze.py tests/test_crash_analyze.py src/likedbg/errors.py
git commit -m "feat(crash): analyze_run shell + CrashError; write crash.json/md, flip run status"
```

---

## Task 7: Config knobs

**Files:**
- Modify: `src/likedbg/config.py:102-118` (`DebuggeeCfg`, `DebuggerCfg`)
- Modify: `configs/default.toml`
- Modify: `tests/test_config_models.py`

**Interfaces:**
- Produces: `DebuggeeCfg.capture_console: bool = True`; `DebuggerCfg.break_on_crash: bool = True`; `DebuggerCfg.crash_breakpoints: tuple[str, ...] = ("panic","die","oops_enter","kasan_report","ubsan_epilogue")`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_config_models.py
from likedbg.config import DebuggeeCfg, DebuggerCfg


def test_crash_config_defaults():
    assert DebuggeeCfg().capture_console is True
    dg = DebuggerCfg()
    assert dg.break_on_crash is True
    assert dg.crash_breakpoints == ("panic", "die", "oops_enter", "kasan_report", "ubsan_epilogue")


def test_crash_breakpoints_overridable():
    dg = DebuggerCfg(crash_breakpoints=["panic", "die"])
    assert dg.crash_breakpoints == ("panic", "die")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config_models.py -k crash -q`
Expected: FAIL — `capture_console` / `break_on_crash` unknown (`extra="forbid"`).

- [ ] **Step 3: Implement**

In `config.py`, add to `DebuggeeCfg` (after `panic`):
```python
    capture_console: bool = True
```
Add to `DebuggerCfg`:
```python
    break_on_crash: bool = True
    crash_breakpoints: tuple[str, ...] = ("panic", "die", "oops_enter", "kasan_report", "ubsan_epilogue")
```
In `configs/default.toml`, extend the sections:
```toml
[debuggee]
memory_mib = 1024
smp = 1
accel = "auto"
network = "auto"
gdb = true
gdb_port = 1234
kaslr = false
smep = true
smap = true
kpti = true
panic = "halt"
capture_console = true

[debugger]
ext = "pwndbg"
break_on_crash = true
crash_breakpoints = ["panic", "die", "oops_enter", "kasan_report", "ubsan_epilogue"]
```

- [ ] **Step 4: Run test + commit**

Run: `uv run pytest tests/test_config_models.py -q && uv run mypy src`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/config.py configs/default.toml tests/test_config_models.py
git commit -m "feat(config): capture_console + break_on_crash + crash_breakpoints"
```

---

## Task 8: `CRASH_DROP_MOUNT` constant

**Files:**
- Modify: `src/likedbg/constants.py`
- Modify: `tests/test_*` (add a tiny assert to an existing constants test or `tests/test_qemu.py` import — see step 1)

**Interfaces:**
- Produces: `constants.CRASH_DROP_MOUNT = "/likedbg-crash"` (container-side path where the gdb payload writes `crash.gdb.json`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crash_constants.py
from likedbg.constants import CRASH_DROP_MOUNT


def test_crash_drop_mount_value():
    assert CRASH_DROP_MOUNT == "/likedbg-crash"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_crash_constants.py -q`
Expected: FAIL — `ImportError: cannot import name 'CRASH_DROP_MOUNT'`.

- [ ] **Step 3: Implement**

Add to `src/likedbg/constants.py`:
```python
CRASH_DROP_MOUNT = "/likedbg-crash"
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_crash_constants.py -q`
Expected: PASS.

```bash
git add src/likedbg/constants.py tests/test_crash_constants.py
git commit -m "feat(constants): CRASH_DROP_MOUNT container path"
```

---

## Task 9: RunRecorder — console/crash paths + `crashed` status

**Files:**
- Modify: `src/likedbg/run_artifacts.py:24` (`RunStatus`), `:96-101` (properties), `:117` (subdirs)
- Modify: `tests/test_run_artifacts.py`

**Interfaces:**
- Produces: `RunStatus` gains `"crashed"`; `RunRecorder.console_raw -> Path` (`logs/console.raw`); `RunRecorder.crash_dir -> Path` (`crash/`, pre-created in `start`).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_run_artifacts.py — reuse the module's existing RunRecorder.start helper/fixtures.
def test_recorder_exposes_console_and_crash_paths(tmp_path):
    rec = _start_recorder(tmp_path)  # existing helper in this test module
    assert rec.console_raw == rec.run_dir / "logs" / "console.raw"
    assert rec.crash_dir == rec.run_dir / "crash"
    assert rec.crash_dir.is_dir()


def test_recorder_accepts_crashed_status(tmp_path):
    rec = _start_recorder(tmp_path)
    rec.set_status("crashed", message="oops")
    import json
    rj = json.loads((rec.run_dir / "run.json").read_text())
    assert rj["status"] == "crashed"
```

> If `tests/test_run_artifacts.py` has no `_start_recorder` helper, construct the recorder the same way the existing tests in that file do (they already call `RunRecorder.start(...)`); reuse their setup verbatim.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_run_artifacts.py -k "console or crashed" -q`
Expected: FAIL — no `console_raw`/`crash_dir`; `set_status("crashed")` is a mypy Literal error.

- [ ] **Step 3: Implement**

In `run_artifacts.py`:
- Line 24 — extend the literal:
```python
RunStatus = Literal[
    "created", "profile-verification-failed", "launching", "launched", "launch-failed", "crashed"
]
```
- Add `"crash"` to the subdirs tuple in `start` (line ~117):
```python
        for sub in ("logs", "commands", "kernel", "profiles", "fragments", "crash"):
```
- Add properties next to `debuggee_pane_log` (~line 96):
```python
    @property
    def console_raw(self) -> Path:
        return self._dir / "logs" / "console.raw"

    @property
    def crash_dir(self) -> Path:
        return self._dir / "crash"
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_run_artifacts.py -q && uv run mypy src/likedbg/run_artifacts.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/run_artifacts.py tests/test_run_artifacts.py
git commit -m "feat(run-artifacts): console_raw + crash_dir paths, crashed status"
```

---

## Task 10: QEMU Console log sink

**Files:**
- Modify: `src/likedbg/qemu.py:40-80` (`build_qemu_argv`)
- Modify: `tests/test_qemu.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `build_qemu_argv(..., console_log: Path | None = None)`. When `console_log` is set, the argv ends with `-chardev stdio,id=cons,logfile=<path>,signal=off -serial chardev:cons -display none` (no `-nographic`, no stdio HMP monitor). When `None`, the existing bare `-nographic` is kept (capture disabled / back-compat).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_qemu.py
from pathlib import Path  # already imported


def test_console_log_uses_chardev_logfile_not_nographic():
    argv = build_qemu_argv(
        _debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"),
        rootfs=None, console_log=Path("/run/logs/console.raw"),
    )
    s = _argstr(argv)
    assert "-chardev" in argv
    assert "stdio,id=cons,logfile=/run/logs/console.raw,signal=off" in s
    assert "-serial chardev:cons" in s
    assert "-display none" in s
    assert "-nographic" not in argv


def test_no_console_log_keeps_nographic():
    argv = build_qemu_argv(_debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None)
    assert "-nographic" in argv
    assert "-chardev" not in argv
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_qemu.py -k console -q`
Expected: FAIL — `build_qemu_argv() got an unexpected keyword argument 'console_log'`.

- [ ] **Step 3: Implement**

Change the signature and the tail of `build_qemu_argv`:
```python
def build_qemu_argv(
    debuggee: DebuggeeCfg,
    host: HostProfile,
    *,
    target_arch: str,
    kernel_image: Path,
    rootfs: Path | None,
    extra_boot_args: tuple[str, ...] = (),
    console_log: Path | None = None,
) -> list[str]:
```
Replace the current `argv += ["-append", append, *drive_args, "-nographic"]` line with:
```python
    argv += ["-append", append, *drive_args]
    if console_log is not None:
        argv += [
            "-chardev", f"stdio,id=cons,logfile={console_log},signal=off",
            "-serial", "chardev:cons",
            "-display", "none",
        ]
    else:
        argv += ["-nographic"]
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_qemu.py -q && uv run mypy src/likedbg/qemu.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/qemu.py tests/test_qemu.py
git commit -m "feat(qemu): dedicated pure-serial Console log sink via chardev logfile="
```

---

## Task 11: Launcher mounts — console-log rw + crash-drop rw

**Files:**
- Modify: `src/likedbg/launchers.py`
- Modify: `tests/test_*` (add `tests/test_launchers_crash.py`)

**Interfaces:**
- Consumes: `CRASH_DROP_MOUNT` (Task 8).
- Produces: `qemu_container_command(..., extra_rw_dirs: tuple[Path, ...] = ())` — binds each dir at its identical path `:rw` (so in-container QEMU can write `console.raw`). `gdb_pane_command(..., crash_drop: Path | None = None)` — adds `-v <crash_drop>:{CRASH_DROP_MOUNT}:rw` when set.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_launchers_crash.py
from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.launchers import gdb_pane_command, qemu_container_command


def test_qemu_container_mounts_extra_rw_dir():
    cmd = qemu_container_command(
        ["qemu-system-x86_64"], image="like_debuggee:latest",
        ro_mounts=[Path("/w/Image")], rw_mounts=[Path("/w/rootfs.img")],
        extra_rw_dirs=(Path("/w/artifacts/runs/r1/logs"),),
    )
    assert "-v /w/artifacts/runs/r1/logs:/w/artifacts/runs/r1/logs:rw" in cmd


def test_gdb_pane_command_adds_crash_drop_mount():
    cmd = gdb_pane_command(
        ["gdb-multiarch"], image="like_debugger:latest", mount_source="/w/ksrc", crash_drop=Path("/w/runs/r1/crash"),
    )
    assert f"-v /w/runs/r1/crash:{CRASH_DROP_MOUNT}:rw" in cmd


def test_gdb_pane_command_no_crash_drop_by_default():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/w/ksrc")
    assert CRASH_DROP_MOUNT not in cmd
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_launchers_crash.py -q`
Expected: FAIL — unexpected kwargs `extra_rw_dirs` / `crash_drop`.

- [ ] **Step 3: Implement**

In `launchers.py`, add the import and extend both functions:
```python
from likedbg.constants import CRASH_DROP_MOUNT  # add near the VOLUME_MOUNT import
```
`gdb_pane_command`:
```python
def gdb_pane_command(
    gdb_args: list[str], *, image: str, mount_source: str, network_mode: str = "published",
    crash_drop: Path | None = None,
) -> str:
    net = "--network host" if network_mode == "host" else "--add-host=host.docker.internal:host-gateway"
    crash = f"-v {shlex.quote(str(crash_drop))}:{CRASH_DROP_MOUNT}:rw " if crash_drop is not None else ""
    docker = f"docker run --rm -it {net} -v {mount_source}:{VOLUME_MOUNT}:ro {crash}{image} "
    return docker + shlex.join(gdb_args)
```
`qemu_container_command` — add the param and one mount line:
```python
def qemu_container_command(
    argv: list[str], *, image: str, ro_mounts: list[Path], rw_mounts: list[Path],
    gdbstub_port: int = 1234, network_mode: str = "published", kvm: bool = False,
    extra_rw_dirs: tuple[Path, ...] = (),
) -> str:
    q = shlex.quote
    mounts = [f"-v {q(str(p))}:{q(str(p))}:ro" for p in ro_mounts]
    mounts += [f"-v {q(str(p))}:{q(str(p))}:rw" for p in rw_mounts]
    mounts += [f"-v {q(str(d))}:{q(str(d))}:rw" for d in extra_rw_dirs]
    net = "--network host" if network_mode == "host" else f"-p {gdbstub_port}:{gdbstub_port}"
    parts = ["docker run --rm -it", net, *mounts]
    if kvm:
        parts.append("--device /dev/kvm")
    parts.append(image)
    docker = " ".join(parts) + " "
    return docker + shlex.join(argv)
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_launchers_crash.py tests/test_qemu.py -q && uv run mypy src/likedbg/launchers.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/launchers.py tests/test_launchers_crash.py
git commit -m "feat(launchers): console-log rw mount + gdb crash-drop rw mount"
```

---

## Task 12: gdb `CrashCapture` payload + `build_gdb_args` crash params

**Files:**
- Modify: `src/likedbg/gdbcmd.py`
- Modify: `tests/test_*` (add `tests/test_gdbcmd_crash.py`)

**Interfaces:**
- Consumes: `CRASH_DROP_MOUNT` (Task 8).
- Produces: `build_gdb_args(host, *, arch, vmlinux, ext, breakpoint, port=1234, break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = (), crash_drop_path: str = CRASH_DROP_MOUNT)`. When `break_on_crash` and `crash_breakpoints`, the argv gains one extra `-ex "python exec(...)"` installing `CrashCapture` breakpoints on those symbols; each `stop()` writes `<crash_drop_path>/crash.gdb.json` and halts. Missing symbols are swallowed.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_gdbcmd_crash.py
from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.gdbcmd import build_gdb_args
from likedbg.host_profile import HostProfile


def _host():
    return HostProfile(
        os="darwin", host_arch="arm64", target_arch="x86_64", accel="tcg",
        debuggee_mode="in-container", storage_mode="volume",
        gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal",
    )


def test_crash_breakpoints_injected_when_enabled():
    args = build_gdb_args(
        _host(), arch="x86_64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel",
        break_on_crash=True, crash_breakpoints=("panic", "die", "kasan_report"),
    )
    joined = "\n".join(args)
    assert "panic" in joined and "die" in joined and "kasan_report" in joined
    assert f"{CRASH_DROP_MOUNT}/crash.gdb.json" in joined
    assert "gdb.Breakpoint" in joined


def test_no_crash_breakpoints_when_disabled():
    args = build_gdb_args(
        _host(), arch="x86_64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel",
        break_on_crash=False, crash_breakpoints=("panic",),
    )
    assert "crash.gdb.json" not in "\n".join(args)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_gdbcmd_crash.py -q`
Expected: FAIL — unexpected kwargs.

- [ ] **Step 3: Implement**

In `gdbcmd.py`, add the import and a payload builder, and extend `build_gdb_args`:
```python
from likedbg.constants import CRASH_DROP_MOUNT  # add to imports


def _crash_capture_source(symbols: tuple[str, ...], out_path: str) -> str:
    source = """
import gdb, json, os

_OUT = %(out)r
_SYMS = %(syms)r


def _regs():
    out = {}
    try:
        frame = gdb.selected_frame()
        for reg in frame.architecture().registers():
            try:
                out[reg.name] = str(frame.read_register(reg.name))
            except Exception:
                pass
    except Exception:
        pass
    return out


def _bt():
    try:
        return gdb.execute("bt", to_string=True).splitlines()
    except Exception:
        return []


class _LikedbgCrash(gdb.Breakpoint):
    def stop(self):
        try:
            os.makedirs(os.path.dirname(_OUT), exist_ok=True)
            with open(_OUT, "w") as fh:
                json.dump({"stopped_at": self.location, "registers": _regs(), "backtrace": _bt()}, fh, indent=2)
            gdb.write("[likedbg] crash captured at %%s -> %%s\\n" %% (self.location, _OUT))
        except Exception as exc:
            gdb.write("[likedbg] crash capture failed: %%s\\n" %% exc)
        return True


for _s in _SYMS:
    try:
        _LikedbgCrash(_s)
    except Exception:
        pass
""" % {"out": out_path, "syms": list(symbols)}
    return f"python exec({source!r})"
```
Extend the signature + append the `-ex` when enabled (place the crash `-ex` right after the reconnect helper `-ex`, before the remote-connect `-ex`, so the breakpoints are installed before `continue`):
```python
def build_gdb_args(
    host: HostProfile, *, arch: str, vmlinux: Path, ext: str, breakpoint: str | None, port: int = 1234,
    break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = (), crash_drop_path: str = CRASH_DROP_MOUNT,
) -> list[str]:
    addr = host.gdbstub_addr
    gdb_arch = _GDB_ARCH.get(arch)
    if gdb_arch is None:
        raise ValueError(f"unsupported gdb architecture: {arch}")
    args = ["gdb-multiarch", "-q"]
    args += ["-iex", f"source {_EXT_SOURCE[ext]}"]
    args += ["-iex", "set auto-load safe-path /", str(vmlinux)]
    args += ["-ex", f"set architecture {gdb_arch}"]
    args += ["-ex", _reconnect_helper(ext, addr, port, breakpoint)]
    if break_on_crash and crash_breakpoints:
        args += ["-ex", _crash_capture_source(crash_breakpoints, f"{crash_drop_path}/crash.gdb.json")]
    args += ["-ex", _remote_command(ext, addr, port)]
    if breakpoint is not None:
        args += ["-ex", f"hbreak {breakpoint}", "-ex", "continue"]
    return args
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_gdbcmd_crash.py -q && uv run mypy src/likedbg/gdbcmd.py`
Expected: PASS; mypy clean. (Also confirm the `%%`/`%` escaping renders literal `%s` in the payload — the test asserts `crash.gdb.json` is present; add a quick `assert "%s" not in ...` only if you want, otherwise trust the live gate.)

```bash
git add src/likedbg/gdbcmd.py tests/test_gdbcmd_crash.py
git commit -m "feat(gdb): CrashCapture breakpoints dump live state to crash.gdb.json"
```

---

## Task 13: Stage threading (debuggee + debugger)

**Files:**
- Modify: `src/likedbg/stages/debuggee.py`, `src/likedbg/stages/debugger.py`
- Modify: `tests/test_*` (extend the existing stage tests, or add `tests/test_stages_crash.py`)

**Interfaces:**
- Consumes: `RunRecorder.console_raw`/`crash_dir` (T9), `build_qemu_argv(console_log=)` (T10), `qemu_container_command(extra_rw_dirs=)` (T11), `build_gdb_args(break_on_crash=, crash_breakpoints=)` (T12).
- Produces: `DebuggeeStage` passes `console_log` (from `recorder.console_raw` when `eff.capture_console`) into the argv and, in-container, mounts the log dir rw. `DebuggerStage.__init__(..., break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = ())` threads them into `build_gdb_args`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_stages_crash.py
from pathlib import Path
from unittest.mock import MagicMock

from likedbg.config import DebuggeeCfg
from likedbg.stages.debugger import DebuggerStage


def test_debugger_stage_passes_crash_config(monkeypatch):
    captured = {}

    def fake_build(*a, **k):
        captured.update(k)
        return ["gdb-multiarch"]

    monkeypatch.setattr("likedbg.stages.debugger.build_gdb_args", fake_build)
    stage = DebuggerStage(ext="pwndbg", run_gdb=lambda args: None, breakpoint="start_kernel",
                          break_on_crash=True, crash_breakpoints=("panic", "die"))
    ctx = MagicMock()
    ctx.vmlinux = Path("/w/vmlinux")
    ctx.host.target_arch = "x86_64"
    ctx.effective_debuggee = DebuggeeCfg()
    ctx.recorder = None
    stage.run(ctx)
    assert captured["break_on_crash"] is True
    assert captured["crash_breakpoints"] == ("panic", "die")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_stages_crash.py -q`
Expected: FAIL — `DebuggerStage.__init__() got an unexpected keyword argument 'break_on_crash'`.

- [ ] **Step 3: Implement**

`stages/debugger.py` — extend `__init__` and the `build_gdb_args` call:
```python
    def __init__(
        self, *, ext: str, run_gdb: Callable[[list[str]], None], breakpoint: str | None,
        break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = (),
    ) -> None:
        self._ext = ext
        self._run_gdb = run_gdb
        self._breakpoint = breakpoint
        self._break_on_crash = break_on_crash
        self._crash_breakpoints = crash_breakpoints
```
```python
        args = build_gdb_args(
            ctx.host, arch=ctx.host.target_arch, vmlinux=ctx.vmlinux, ext=self._ext,
            breakpoint=self._breakpoint, port=eff.gdb_port,
            break_on_crash=self._break_on_crash, crash_breakpoints=self._crash_breakpoints,
        )
```
`stages/debuggee.py` — compute `console_log` + `extra_rw_dirs` and pass them:
```python
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        console_log = None
        if eff.capture_console and ctx.recorder is not None:
            console_log = ctx.recorder.console_raw  # type: ignore[attr-defined]
        argv = build_qemu_argv(
            eff, ctx.host, target_arch=ctx.host.target_arch, kernel_image=ctx.kernel_image,
            rootfs=ctx.rootfs_image, extra_boot_args=ctx.extra_boot_args, console_log=console_log,
        )
        if ctx.host.debuggee_mode == "in-container":
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            extra_rw = (console_log.parent,) if console_log is not None else ()
            cmd = qemu_container_command(
                argv, image=self._debuggee_image, ro_mounts=[ctx.kernel_image], rw_mounts=rw_mounts,
                gdbstub_port=eff.gdb_port, network_mode=ctx.host.network_mode,
                kvm=ctx.host.accel == "kvm", extra_rw_dirs=extra_rw,
            )
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_stages_crash.py tests/test_qemu.py -q && uv run mypy src/likedbg/stages`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py tests/test_stages_crash.py
git commit -m "feat(stages): thread console log + crash breakpoints through debuggee/debugger"
```

---

## Task 14: CLI pipeline wiring

**Files:**
- Modify: `src/likedbg/cli.py` (`build_pipeline`, `build_use_pipeline`, `run_gdb` closures, `cmd_use`, `main`)
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: T13 stage params, `RunRecorder.crash_dir`, `gdb_pane_command(crash_drop=)`.
- Produces: `build_pipeline`/`build_use_pipeline` gain `break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = ()`, pass them to `DebuggerStage`, and the `run_gdb` closures pass `crash_drop=recorder.crash_dir` (when `recorder`) to `gdb_pane_command`. `main`/`cmd_use` source them from `cfg.settings.debugger`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_cli.py — assert the DebuggerStage in the built pipeline carries crash config.
from likedbg.cli import build_pipeline
# (Reuse whatever ContainerService/Session fakes the existing test_cli.py already defines.)


def test_build_pipeline_passes_crash_config(cli_fakes):  # cli_fakes = existing fixture in test_cli.py
    container, session, host, br, rr = cli_fakes
    pipe = build_pipeline(
        container, session, host=host, workspace=Path("/w"), kernel_volume="likedbg_ksrc",
        dl_dir=Path("/w/kernels"), debugger_image="dbg", debuggee_image="dbge", ext="pwndbg",
        build_recipe=br, rootfs_recipe=rr, break_on_crash=True, crash_breakpoints=("panic", "die"),
    )
    dbg = pipe._stages[-1]
    assert dbg._break_on_crash is True and dbg._crash_breakpoints == ("panic", "die")
```

> Match the exact fixture/fake names already in `tests/test_cli.py`. If the file builds the pipeline differently, mirror its existing call and only add the two new kwargs + assertions.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_cli.py -k crash -q`
Expected: FAIL — `build_pipeline() got an unexpected keyword argument 'break_on_crash'`.

- [ ] **Step 3: Implement**

- Add `break_on_crash: bool = False, crash_breakpoints: tuple[str, ...] = ()` to both `build_pipeline` and `build_use_pipeline` signatures.
- In each, change the final stage to:
```python
            DebuggerStage(
                ext=ext, run_gdb=run_gdb, breakpoint="start_kernel",
                break_on_crash=break_on_crash, crash_breakpoints=crash_breakpoints,
            ),
```
- In each `run_gdb` closure, pass the crash drop:
```python
        cmd = gdb_pane_command(
            args, image=debugger_image, mount_source=loc.gdb_mount_source, network_mode=host.network_mode,
            crash_drop=recorder.crash_dir if recorder is not None else None,
        )
```
(In `build_use_pipeline`, `mount_source=gdb_mount_source`.)
- In `main` (default run) pass from config to `build_pipeline`:
```python
            break_on_crash=cfg.settings.debugger.break_on_crash,
            crash_breakpoints=cfg.settings.debugger.crash_breakpoints,
```
- In `cmd_use` pass to `build_use_pipeline`:
```python
        break_on_crash=use_settings.debugger.break_on_crash,
        crash_breakpoints=use_settings.debugger.crash_breakpoints,
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_cli.py -q && uv run mypy src/likedbg/cli.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): wire crash breakpoints + crash-drop mount into the pipelines"
```

---

## Task 15: `--analyze-crash` command

**Files:**
- Modify: `src/likedbg/cli.py` (`main` argparse + a `cmd_analyze_crash` helper)
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `analyze_run` (T6).
- Produces: `cmd_analyze_crash(workspace: Path, *, run_id: str) -> int`; `--analyze-crash [RUN-ID]` (`nargs="?"`, `const="latest"`). Resolves `latest` → `artifacts/runs/latest`; a bare id → `artifacts/runs/<id>`. Pure host — dispatched before any Docker/tmux, right beside `--explain-config`. Prints a one-line summary + report paths, or "no crash detected".

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_cli.py
import json
from likedbg.cli import cmd_analyze_crash


def test_cmd_analyze_crash_writes_report(tmp_path, capsys):
    run = tmp_path / "artifacts" / "runs" / "20260704T000000Z-linux-6.6.30-x"
    (run / "logs").mkdir(parents=True)
    (run / "crash").mkdir()
    (run / "logs" / "console.raw").write_text("[ 1.0] Kernel panic - not syncing: test\n")
    (run / "host.json").write_text(json.dumps({"target_arch": "x86_64"}))
    (run / "run.json").write_text(json.dumps({"status": "launched", "build_label": "linux-6.6.30-x", "status_history": []}))
    rc = cmd_analyze_crash(tmp_path, run_id=run.name)
    assert rc == 0
    assert (run / "crash.json").is_file()
    assert "panic" in capsys.readouterr().out


def test_cmd_analyze_crash_no_crash(tmp_path, capsys):
    run = tmp_path / "artifacts" / "runs" / "r2"
    (run / "logs").mkdir(parents=True)
    (run / "logs" / "console.raw").write_text("[ 0.1] booting\n")
    (run / "host.json").write_text(json.dumps({"target_arch": "x86_64"}))
    (run / "run.json").write_text(json.dumps({"status": "launched", "build_label": "linux-6.6.30-x"}))
    assert cmd_analyze_crash(tmp_path, run_id="r2") == 0
    assert "no crash detected" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_cli.py -k analyze -q`
Expected: FAIL — `cannot import name 'cmd_analyze_crash'`.

- [ ] **Step 3: Implement**

Add the import and the helper to `cli.py`:
```python
from likedbg.crash.analyze import analyze_run  # add to imports


def cmd_analyze_crash(workspace: Path, *, run_id: str) -> int:
    runs = workspace / "artifacts" / "runs"
    run_dir = (runs / "latest") if run_id == "latest" else (runs / run_id)
    run_dir = run_dir.resolve() if run_dir.is_symlink() else run_dir
    report = analyze_run(run_dir)
    if report is None:
        logger.info("no crash detected")
        print("no crash detected")
        return 0
    prim = report.events[report.primary] if report.primary is not None else report.events[0]
    print(f"crash: {prim.kind} — {prim.title}")
    print(f"  report: {run_dir / 'crash.md'}")
    print(f"  json:   {run_dir / 'crash.json'}")
    return 0
```
Add the argparse option (next to `--explain-config`):
```python
    parser.add_argument("--analyze-crash", nargs="?", const="latest", default=None, metavar="RUN-ID")
```
Add the dispatch inside `main`'s `try`, right after the `--explain-config` block (before `--restart-debuggee`), so it stays Docker/tmux-free:
```python
        if args.analyze_crash is not None:
            return cmd_analyze_crash(workspace, run_id=args.analyze_crash)
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_cli.py -q && uv run mypy src/likedbg/cli.py`
Expected: PASS; mypy clean.

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): --analyze-crash [run-id] (pure host, Docker/tmux-free)"
```

---

## Task 16: Soft `CONFIG_KALLSYMS` profile expectation

**Files:**
- Modify: `configs/profiles/exploit-dev.toml`, `configs/profiles/crash-debug.toml`, `configs/profiles/kasan.toml`, `configs/profiles/ubsan.toml`
- Modify: `tests/test_builtin_profiles.py` (or `tests/test_debug_profiles_verify.py` — whichever asserts profile expectations)

**Interfaces:**
- Produces: each listed profile carries a `soft` `CONFIG_KALLSYMS=y` expectation, so a build lacking it warns (not fails).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_builtin_profiles.py — assert the loaded exploit-dev profile expects CONFIG_KALLSYMS soft.
def test_exploit_dev_expects_kallsyms_soft():
    prof = _load_profile("exploit-dev")  # reuse this module's existing profile loader/helper
    exp = {e.symbol: e for e in prof.expected_config}
    assert "CONFIG_KALLSYMS" in exp
    assert exp["CONFIG_KALLSYMS"].value == "y" and exp["CONFIG_KALLSYMS"].severity == "soft"
```

> Use whatever helper `tests/test_builtin_profiles.py` already uses to load a profile's resolved expectations. If none exists, load via the same `resolve_run`/registry path the other tests in that file use.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_builtin_profiles.py -k kallsyms -q`
Expected: FAIL — no `CONFIG_KALLSYMS` expectation.

- [ ] **Step 3: Implement**

Append this block to each of the four profile TOMLs (`exploit-dev.toml`, `crash-debug.toml`, `kasan.toml`, `ubsan.toml`):
```toml
[[expect]]
symbol = "CONFIG_KALLSYMS"
value = "y"
severity = "soft"
```

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_builtin_profiles.py tests/test_debug_profiles_verify.py -q`
Expected: PASS.

```bash
git add configs/profiles/exploit-dev.toml configs/profiles/crash-debug.toml configs/profiles/kasan.toml configs/profiles/ubsan.toml tests/test_builtin_profiles.py
git commit -m "feat(profiles): soft CONFIG_KALLSYMS expectation for symbolized traces"
```

---

## Task 17: `.tmux.conf` `pane-died` auto-analyze hook

**Files:**
- Modify: `.tmux.conf`

**Interfaces:**
- Produces: a global `pane-died` hook that, when the died pane is the stored Debuggee pane, runs `start_kgdb --analyze-crash` in the workspace. Guarded on `@likedbg_debuggee_pane` (set by `build_pipeline`) and `@likedbg_workspace`. Best-effort; the manual command is the primary path.

- [ ] **Step 1: Add the hook**

Append to `.tmux.conf` (mirrors the existing `bind B run-shell` workspace pattern):
```tmux
# LIKE-DBG: when the Debuggee pane's process exits (e.g. panic->reboot), auto-generate the crash report.
# Best-effort; the primary path is `start_kgdb --analyze-crash` run manually while stopped in GDB.
set-hook -g pane-died 'if-shell -F "#{&&:#{!=:#{@likedbg_debuggee_pane},},#{==:#{hook_pane},#{@likedbg_debuggee_pane}}}" "run-shell -b \"cd #{@likedbg_workspace} && uv run ./start_kgdb --analyze-crash >/dev/null 2>&1\""'
```

- [ ] **Step 2: Sanity-parse the config**

Run: `tmux -L likedbg-planlint -f .tmux.conf new -d 'true' \; kill-server 2>&1 | head`
Expected: no parse error printed (the hook line loads). If tmux is unavailable in the environment, defer this check to the live gate (Task 18).

- [ ] **Step 3: Commit**

```bash
git add .tmux.conf
git commit -m "feat(tmux): pane-died hook auto-runs --analyze-crash on Debuggee exit"
```

> Full validation is at the live gate — a `pane-died` hook firing the right command with the right run only demonstrably works end-to-end on a real boot.

---

## Task 18: Live gate + full-suite verification + roadmap update

**Files:**
- Modify: `docs/superpowers/ROADMAP.md`

**This task is verification, not new code. Do NOT skip; capture evidence.**

- [ ] **Step 1: Full local gate**

Run:
```bash
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src && uv run pytest -q
```
Expected: all green. Record the pytest count.

- [ ] **Step 2: Live gate — arm64 (M5) and/or x86_64 (in-container / Ubuntu VM)**

Use the `verify` skill / controller-driven live gate. Procedure per arch:
1. `tmux -L likedbg -f .tmux.conf new -s LIKE-DBG`; inside it `uv run ./start_kgdb` (a `crash-debug` or `kasan` profile).
2. At the `start_kernel` stop, `continue` to userspace.
3. Trigger a crash from the guest shell: `echo c > /proc/sysrq-trigger` (panic). For KASAN, boot a `kasan` profile and trigger a `lib/test_kasan` UAF (or a tiny null-deref module for an oops).
4. Confirm: gdb **halts at the fault** with live registers; `[likedbg] crash captured` marker printed; `artifacts/runs/latest/crash/crash.gdb.json` exists.
5. Run `uv run ./start_kgdb --analyze-crash` → `crash.json` + `crash.md` written; `run.json` status `crashed`; the trace is symbolized; `console.raw` is pure serial (no monitor bytes).
6. Verify the `pane-died` hook path: a panic-with-reboot (temporarily `panic = "reboot"`) auto-generates the report on QEMU exit.

Record a short transcript under `docs/superpowers/notes/2026-07-04-crash-intel-live.md`.

- [ ] **Step 2b: Systematic-debugging if the gate trips**

If `die`'s `pt_regs` doesn't resolve, or the in-container `logfile=` path isn't writable, or KASAN shape differs: use `superpowers:systematic-debugging` (root cause before fixes). Known risk spots: §12 of the spec.

- [ ] **Step 3: Mark B3 done in the roadmap**

Update `docs/superpowers/ROADMAP.md` §D: mark **B3 (Crash intelligence)** DONE + live-gated + the branch/commit range; note the `feat/exploit-loop` branch is next (Branch 2).

- [ ] **Step 4: Commit + finish the branch**

```bash
git add docs/superpowers/ROADMAP.md docs/superpowers/notes/2026-07-04-crash-intel-live.md
git commit -m "docs(roadmap): B3 crash intelligence DONE + live-gate transcript"
```
Then use `superpowers:finishing-a-development-branch` to merge `feat/crash-intel` into `dev` **locally** and delete the branch.

---

## Self-Review (completed at authoring)

**Spec coverage:** §1 purpose → all tasks; §2 goals → T2/T3 (classes), T6/T15 (analyze + CLI), T10 (sink), T7 (config), T16 (KALLSYMS expectation); §3 decisions 1–6 → T10, T2–T6, T15/T17, T9, T12, T7; §4 modules → T1–T6 + wiring T7–T15; §5 data flow → T9–T14 + T6; §6 schema/status → T1/T6/T9; §7 panic-break → T12; §8 config → T7; §9 CLI/teardown → T15/T17; §10 errors → T6 (+ parse edge cases T3); §11 testing → every task's tests + T18 live gate; §13 docs → already committed (ADR-0007, CONTEXT.md); ROADMAP → T18. No gaps.

**Placeholder scan:** every code step carries complete code; fixtures are literal; the two "reuse the existing test helper" notes point at concrete existing patterns (`RunRecorder.start`, the profile loader) rather than leaving code blank.

**Type consistency:** `parse_console(text, arch)`, `merge_gdb_live(events, dict)`, `render_json/markdown(report)`, `analyze_run(run_dir)`, `build_qemu_argv(..., console_log=)`, `gdb_pane_command(..., crash_drop=)`, `qemu_container_command(..., extra_rw_dirs=)`, `build_gdb_args(..., break_on_crash=, crash_breakpoints=, crash_drop_path=)`, `DebuggerStage(..., break_on_crash=, crash_breakpoints=)`, `CRASH_DROP_MOUNT`, `RunRecorder.console_raw/crash_dir`, `CrashError` — names used identically across producer/consumer tasks.
