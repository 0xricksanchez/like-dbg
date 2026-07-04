"""Parse a raw serial Console log into CrashEvents. Arch-shared scaffold + thin
arch-specific register/fault-line handling. Frames are taken as the kernel symbolized
them (CONFIG_KALLSYMS); raw-hex frames are kept raw. No System.map (ADR-0007).

A single fault prints an onset line (``BUG: kernel NULL pointer...`` /
``Unable to handle kernel...``) followed a few lines later by an ``Oops: ... [#1]``
continuation line. Both belong to the same CrashEvent: a new event is only started
when no event is currently open, so the continuation line does not spawn a second
event. Blank/timestamp-only lines are skipped without closing the open event, so
gaps mid-dump never drop the fault PC or the remaining trace.
"""

from __future__ import annotations

import re

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import Frame
from likedbg.crash.model import KasanInfo

# Strip the leading "[   12.345678] " dmesg timestamp so patterns match the message.
_TS = re.compile(r"^\[\s*\d+\.\d+\]\s?")
# A printed call-trace frame: "func+0x1a/0x40" optionally "[module]".
_FRAME = re.compile(r"^([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+(?:\s+\[(\w+)\])?$")
_X86_RIP = re.compile(r"^RIP:\s*[0-9a-fA-F]+:([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+")
_X86_REG = re.compile(r"^(R[A-Z0-9]{2}|RIP|RSP|EFLAGS):")
_ARM_PC = re.compile(r"^pc :\s*([A-Za-z_][\w.]*)\+0x([0-9a-fA-F]+)/0x[0-9a-fA-F]+")
_ARM_REG = re.compile(r"^(pc|lr|sp|x\d+) :")
_ADDR = re.compile(r"address:?\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)")
# A non-symbolic trace frame still carries a hex address: bare/"0x" or an
# old-style "[<ffffffff...>]" entry. Requires a run of hex so markers like
# "<TASK>" (handled separately) never register as a frame.
_RAW_FRAME_HEX = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{6,}")

# Fault-onset markers -> (kind, fatal). Order matters: first match on a line wins.
_ONSET: list[tuple[re.Pattern[str], str, bool]] = [
    (re.compile(r"^Kernel panic - not syncing:\s*(?P<msg>.*)"), "panic", True),
    (re.compile(r"^BUG: KASAN:"), "kasan", True),
    (re.compile(r"^BUG: kernel NULL pointer dereference"), "oops", True),
    (re.compile(r"^Unable to handle kernel"), "oops", True),
    (re.compile(r"^Oops:\s"), "oops", True),
    (re.compile(r"^UBSAN:\s*(?P<msg>.*)"), "ubsan", True),
    (re.compile(r"^WARNING: CPU:.*at .*\s(?P<msg>\S+\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)"), "warn", False),
]

# KASAN "Read/Write of size N at addr <hex>" access-detail line.
_KASAN_ACCESS = re.compile(r"(Read|Write) of size (\d+) at addr ([0-9a-fA-F]+)")
# Markers that show the capture ended mid-fault (reboot/panic-end banners), so
# whatever trace/registers were captured so far may be incomplete.
_REBOOT = re.compile(r"Rebooting in |Kernel Offset: |---\[ end Kernel panic")


def normalize(text: str) -> str:
    """CRLF/lone-CR -> LF (tty capture carries \\r\\n; see the B1 .config CRLF fix)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _strip(line: str) -> str:
    return _TS.sub("", line).rstrip()


def _is_raw_frame(body: str) -> bool:
    """A non-symbolic trace line that is still clearly a frame (keeps raw hex)."""
    if not body or body.startswith("<"):  # skip "<TASK>" / "</TASK>" markers
        return False
    return "+0x" in body or bool(_RAW_FRAME_HEX.search(body))


def _frame(line: str) -> Frame | None:
    body = _strip(line).strip()
    m = _FRAME.match(body)
    if m:
        return Frame(raw=body, symbol=m.group(1), offset=int(m.group(2), 16), module=m.group(3))
    if _is_raw_frame(body):
        return Frame(raw=body, symbol=None, offset=None)
    return None


def _classify(body: str) -> tuple[str, bool, str] | None:
    for pat, kind, fatal in _ONSET:
        m = pat.match(body)
        if m:
            title = m.groupdict().get("msg") or body
            return kind, fatal, title.strip()
    return None


def _maybe_fault_addr(ev: CrashEvent, body: str) -> None:
    m = _ADDR.search(body)
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


def parse_console(text: str, arch: str) -> list[CrashEvent]:
    lines = normalize(text).splitlines()
    events: list[CrashEvent] = []
    cur: CrashEvent | None = None
    in_trace = False
    for raw_line in lines:
        body = _strip(raw_line)
        if not body:
            # Blank / timestamp-only line: skip it, but keep the open event and
            # trace state so a mid-dump gap never drops the fault PC or trace.
            continue
        # Only start a new event when no fault is currently open: a continuation
        # line of an already-open fault (e.g. the "Oops: ... [#1]" line that
        # follows a "BUG: kernel NULL pointer..." onset) must not open a second
        # event for the same fault.
        onset = _classify(body) if cur is None else None
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
        if cur.kind == "kasan":
            km = _KASAN_ACCESS.search(body)
            if km:
                cur.kasan = KasanInfo(access=km.group(1).lower(), size=int(km.group(2)), bad_addr=km.group(3))
        if _REBOOT.search(body):
            cur.incomplete = True
        # Trace start markers.
        if body.startswith(("Call Trace:", "Call trace:")):
            in_trace = True
            continue
        # Registers / fault PC (arch-specific).
        if arch == "x86_64":
            _x86_line(cur, body)
        else:
            _arm_line(cur, body)
        # Frames inside the trace. Genuine call-trace entries stay indented after
        # the timestamp is stripped; the post-trace tail ("CR2:", "Modules linked
        # in:", "---[ end trace ]---", the repeated "RIP:"/"RSP:") starts at column
        # 0. A non-indented line therefore ends the trace section and is not
        # captured. "<TASK>"/"</TASK>" markers are indented but excluded by _frame.
        if in_trace:
            if not body[:1].isspace():
                in_trace = False
            else:
                fr = _frame(body)
                if fr is not None:
                    cur.trace.append(fr)
    for ev in events:
        # A KASAN report always ends with a "====" banner line; its absence means
        # the capture was cut off before the report finished printing.
        if ev.kind == "kasan" and not any(set(line) == {"="} for line in ev.message_lines[1:]):
            ev.incomplete = True
    return events
