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
Accel = Literal["auto", "kvm", "hvf", "tcg"]
MacStorage = Literal["auto", "bind", "volume"]
BuildMode = Literal["generic", "syzkaller", "custom", "config"]
Compiler = Literal["clang", "gcc"]
Ext = Literal["gef", "pwndbg"]


class _Base(BaseModel):
    # Pydantic v2 lax coercion turns INI strings like "yes"/"no"/"1024" into bool/int,
    # so no custom validators are needed. Blank INI values are dropped by the loader, so
    # model defaults apply rather than empty strings.
    model_config = ConfigDict(frozen=True, extra="forbid")


class GeneralCfg(_Base):
    arch: Arch = "x86_64"
    kernel_tag: str = ""
    workspace_dir: str | None = None
    mac_storage: MacStorage = "auto"


class KernelDlCfg(_Base):
    mmp: str | None = None
    tag: str | None = None
    commit: str | None = None


class KernelBuilderCfg(_Base):
    compiler: Compiler = "clang"
    toolchain: str = "auto"
    mode: BuildMode = "generic"
    rust: bool = False
    extra_args: str | None = None
    patch_dir: str | None = None
    custom_modules: str | None = None


class RootfsCfg(_Base):
    distribution: str = "bookworm"
    hostname: str = "LIKE-DBG"


class DebuggeeCfg(_Base):
    memory: int = 1024
    smp: int = 1
    kvm: bool = False
    gdb: bool = True
    kaslr: bool = False
    smep: bool = True
    smap: bool = True
    kpti: bool = True
    panic: str = "halt"
    accel: Accel = "auto"


class DebuggerCfg(_Base):
    ext: Ext = "gef"


class Settings(_Base):
    general: GeneralCfg = GeneralCfg()
    kernel_dl: KernelDlCfg = KernelDlCfg()
    kernel_builder: KernelBuilderCfg = KernelBuilderCfg()
    rootfs: RootfsCfg = RootfsCfg()
    debuggee: DebuggeeCfg = DebuggeeCfg()
    debugger: DebuggerCfg = DebuggerCfg()


_SECTION_MODEL: dict[str, type[_Base]] = {
    "general": GeneralCfg,
    "kernel_dl": KernelDlCfg,
    "kernel_builder": KernelBuilderCfg,
    "rootfs": RootfsCfg,
    "debuggee": DebuggeeCfg,
    "debugger": DebuggerCfg,
}


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
        kernel_dl=cast(KernelDlCfg, _build("kernel_dl", KernelDlCfg)),
        kernel_builder=cast(KernelBuilderCfg, _build("kernel_builder", KernelBuilderCfg)),
        rootfs=cast(RootfsCfg, _build("rootfs", RootfsCfg)),
        debuggee=cast(DebuggeeCfg, _build("debuggee", DebuggeeCfg)),
        debugger=cast(DebuggerCfg, _build("debugger", DebuggerCfg)),
    )
