"""Typed configuration models plus the INI and TOML config loaders.

Two loaders currently coexist (the INI loader is removed in a later task):
- ``load_settings``: legacy two-tier INI loader. Precedence (lowest → highest):
  system.ini ◁ user.ini ◁ custom.ini ◁ overrides (CLI). Blank INI values are
  treated as "unset" so model defaults apply.
- ``load_config``: the 6-layer TOML loader producing whole-Settings provenance
  (built-in ◁ default ◁ profile ◁ local ◁ scenario ◁ cli).
"""

from __future__ import annotations

import configparser
import tomllib
from dataclasses import dataclass
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


# ---------------------------------------------------------------------------
# TOML 6-layer loader (replaces INI loader in Task 16/18)
# ---------------------------------------------------------------------------

LAYER_BUILTIN = "built-in"
LAYER_DEFAULT = "default"
LAYER_PROFILE = "profile"
LAYER_LOCAL = "local"
LAYER_SCENARIO = "scenario"
LAYER_CLI = "cli"

_SECTION_MODELS: dict[str, type[_Base]] = {
    "general": GeneralCfg,
    "source": SourceCfg,
    "build": BuildCfg,
    "rootfs": RootfsCfg,
    "debuggee": DebuggeeCfg,
    "debugger": DebuggerCfg,
    "debugging": DebuggingCfg,
}

# Section→key→value layer dict.
_Layer = dict[str, dict[str, object]]


def _read_toml(path: Path) -> _Layer:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    # tomllib gives nested dicts already keyed by section.
    return {sec: dict(kv) for sec, kv in data.items() if isinstance(kv, dict)}


def _merge(layers: list[tuple[str, _Layer]]) -> tuple[dict[str, dict[str, object]], dict[tuple[str, str], str]]:
    """Apply ordered (low→high) layers; return merged section dicts + winning-layer provenance."""
    merged: dict[str, dict[str, object]] = {}
    prov: dict[tuple[str, str], str] = {}
    for name, layer in layers:
        for section, kv in layer.items():
            for key, val in kv.items():
                merged.setdefault(section, {})[key] = val
                prov[(section, key)] = name
    return merged, prov


def _build_settings(merged: dict[str, dict[str, object]]) -> Settings:
    kwargs: dict[str, _Base] = {}
    for section, model in _SECTION_MODELS.items():
        try:
            kwargs[section] = model(**merged.get(section, {}))
        except ValidationError as exc:
            raise ConfigError(
                f"invalid [{section}] configuration: {exc.errors()[0]['msg']}",
                remedy=f"check the [{section}] section of your TOML config",
            ) from exc
    return Settings(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class ConfigResolution:
    settings: Settings
    provenance: dict[tuple[str, str], str]
    _ordered_layers: tuple[tuple[str, _Layer], ...]  # built-in placeholder excluded; low→high

    def effective_debuggee(self, profile_defaults: dict[str, str]) -> tuple[DebuggeeCfg, dict[tuple[str, str], str]]:
        """Re-merge [debuggee] with profile defaults spliced in at layer 4 (above default, below local)."""
        # load_config always inserts LAYER_DEFAULT first, so the profile layer is
        # guaranteed to splice in right above it (no fallback path needed).
        rebuilt: list[tuple[str, _Layer]] = []
        for name, layer in self._ordered_layers:
            rebuilt.append((name, layer))
            if name == LAYER_DEFAULT and profile_defaults:
                rebuilt.append((LAYER_PROFILE, {"debuggee": dict(profile_defaults)}))
        merged, prov = _merge(rebuilt)
        return _build_settings(merged).debuggee, prov


def load_config(
    workspace: Path,
    *,
    scenario: Path | None = None,
    cli_overrides: dict[str, dict[str, str]] | None = None,
) -> ConfigResolution:
    default_path = workspace / "configs" / "default.toml"
    if not default_path.exists():
        raise ConfigError(
            f"project config not found: {default_path}",
            remedy="create configs/default.toml (see configs/local.example.toml)",
        )
    layers: list[tuple[str, _Layer]] = [(LAYER_DEFAULT, _read_toml(default_path))]
    local_path = workspace / "configs" / "local.toml"
    if local_path.exists():
        layers.append((LAYER_LOCAL, _read_toml(local_path)))
    if scenario is not None:
        if not scenario.exists():
            raise ConfigError(f"scenario config not found: {scenario}", remedy="check the -c name/path")
        layers.append((LAYER_SCENARIO, _read_toml(scenario)))
    if cli_overrides:
        layers.append((LAYER_CLI, {sec: dict(kv) for sec, kv in cli_overrides.items()}))
    merged, prov = _merge(layers)
    return ConfigResolution(settings=_build_settings(merged), provenance=prov, _ordered_layers=tuple(layers))
