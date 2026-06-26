"""Typed configuration parsed from the two-tier INI files.

Precedence (lowest → highest): system.ini ◁ user.ini ◁ custom.ini ◁ overrides (CLI).
Blank INI values are treated as "unset" so model defaults apply.
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Literal
from typing import cast

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError

from likedbg.errors import ConfigError

Arch = Literal["x86_64", "arm64"]
RequestedArch = Literal["native", "x86_64", "arm64"]
Accel = Literal["auto", "kvm", "hvf", "tcg"]
MacStorage = Literal["auto", "bind", "volume"]
SourceKind = Literal["mmp", "tag", "commit"]
Compiler = Literal["clang", "gcc"]
Ext = Literal["gef", "pwndbg"]
Network = Literal["auto", "host", "published"]


class _Base(BaseModel):
    # Pydantic v2 lax coercion turns INI strings like "yes"/"no"/"1024" into bool/int,
    # so no custom validators are needed. Blank INI values are dropped by the loader, so
    # model defaults apply rather than empty strings.
    model_config = ConfigDict(frozen=True, extra="forbid")


class GeneralCfg(_Base):
    arch: RequestedArch = "native"
    workspace_dir: str | None = None
    mac_storage: MacStorage = "auto"


class SourceCfg(_Base):
    kind: SourceKind = "mmp"
    value: str = ""


class BuildCfg(_Base):
    compiler: Compiler = "clang"
    toolchain: str = "auto"
    rust: bool = False
    label_suffix: str = ""
    patch_dirs: tuple[str, ...] = ()
    custom_modules: tuple[str, ...] = ()  # B1: validated schema slot only; built in B6.
    extra_fragments: tuple[str, ...] = ()


class RootfsCfg(_Base):
    distribution: str = "bookworm"
    hostname: str = "LIKE-DBG"


class DebuggeeCfg(_Base):
    memory_mib: int = 1024
    smp: int = 1
    accel: Accel = "auto"
    network: Network = "auto"
    gdb: bool = True
    gdb_port: int = 1234
    kaslr: bool = False
    smep: bool = True
    smap: bool = True
    kpti: bool = True
    panic: str = "halt"


class DebuggerCfg(_Base):
    ext: Ext = "pwndbg"


class DebuggingCfg(_Base):
    profiles: tuple[str, ...] = ("exploit-dev",)


class KernelDlCfg(_Base):
    """Temporary stub; remove in Task 3/Task 14 when loader replaces INI."""

    pass


class Settings(_Base):
    general: GeneralCfg = GeneralCfg()
    source: SourceCfg = SourceCfg()
    build: BuildCfg = BuildCfg()
    rootfs: RootfsCfg = RootfsCfg()
    debuggee: DebuggeeCfg = DebuggeeCfg()
    debugger: DebuggerCfg = DebuggerCfg()
    debugging: DebuggingCfg = DebuggingCfg()


def _layer(into: dict[str, dict[str, str]], cfg: configparser.ConfigParser) -> None:
    """Merge non-blank keys from a parsed INI onto the accumulator (later wins)."""
    for section in cfg.sections():
        for key, val in cfg[section].items():
            if val.strip() == "":
                continue  # blank == unset; keep the lower layer / default
            into.setdefault(section, {})[key] = val


def _read(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}", remedy=f"create {path}")
    cfg.read(path)
    return cfg


def load_settings(
    system_ini: Path,
    user_ini: Path,
    *,
    custom_ini: Path | None = None,
    overrides: dict[str, dict[str, str]] | None = None,
) -> Settings:
    merged: dict[str, dict[str, str]] = {}
    _layer(merged, _read(system_ini))
    _layer(merged, _read(user_ini))
    if custom_ini is not None:
        _layer(merged, _read(custom_ini))
    if overrides:
        for section, kv in overrides.items():
            merged.setdefault(section, {}).update(kv)

    def _build(section: str, model: type[_Base]) -> _Base:
        try:
            return model(**merged.get(section, {}))
        except ValidationError as exc:
            raise ConfigError(
                f"invalid [{section}] configuration: {exc.errors()[0]['msg']}",
                remedy=f"check the [{section}] section of your .ini",
            ) from exc

    return Settings(
        general=cast(GeneralCfg, _build("general", GeneralCfg)),
        source=cast(SourceCfg, _build("source", SourceCfg)),
        build=cast(BuildCfg, _build("build", BuildCfg)),
        rootfs=cast(RootfsCfg, _build("rootfs", RootfsCfg)),
        debuggee=cast(DebuggeeCfg, _build("debuggee", DebuggeeCfg)),
        debugger=cast(DebuggerCfg, _build("debugger", DebuggerCfg)),
        debugging=cast(DebuggingCfg, _build("debugging", DebuggingCfg)),
    )
