"""Render a CrashReport as JSON (dict) and blog-ready Markdown."""

from __future__ import annotations

from typing import Any

from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport
from likedbg.crash.model import Frame


def render_json(report: CrashReport) -> dict[str, Any]:
    return report.to_dict()


def _frame_line(f: Frame) -> str:
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
