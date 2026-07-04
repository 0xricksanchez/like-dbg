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
