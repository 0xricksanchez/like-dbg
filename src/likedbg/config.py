"""Typed configuration models plus the TOML config loader.

``load_config``: the 6-layer TOML loader producing whole-Settings provenance
(built-in < default < profile < local < scenario < cli).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError
from pydantic import field_validator

from likedbg.errors import ConfigError

_FRAGMENTS_PREFIX = "configs/fragments/"


def _reject_unsafe_path(p: str) -> None:
    """Raise ConfigError if p is absolute or contains '..' traversal."""
    pp = Path(p)
    if pp.is_absolute():
        raise ConfigError(
            f"unsafe path {p!r}: absolute paths are not allowed",
            remedy="use a workspace-relative path (e.g. 'patches/my-fix')",
        )
    if ".." in pp.parts:
        raise ConfigError(
            f"unsafe path {p!r}: '..' traversal is not allowed",
            remedy="use a forward-only relative path",
        )


def _reject_traversal(p: str) -> None:
    """Raise ConfigError only on '..' traversal; absolute paths are allowed.

    Foreign inputs are read-only external artifacts a CTF challenge ships anywhere
    (e.g. ~/ctf/<name>/), so absolute paths are permitted here, unlike _reject_unsafe_path.
    """
    if ".." in Path(p).parts:
        raise ConfigError(
            f"unsafe path {p!r}: '..' traversal is not allowed",
            remedy="use a forward-only path (absolute or workspace-relative)",
        )


Arch = Literal["x86_64", "arm64"]
RequestedArch = Literal["native", "x86_64", "arm64"]
Accel = Literal["auto", "kvm", "hvf", "tcg"]
MacStorage = Literal["auto", "bind", "volume"]
SourceKind = Literal["version", "tag", "commit"]
Compiler = Literal["clang", "gcc"]
Ext = Literal["gef", "pwndbg"]
Network = Literal["auto", "host", "published"]
Debuginfod = Literal["auto", "on", "off"]


class _Base(BaseModel):
    # Pydantic v2 lax coercion turns INI strings like "yes"/"no"/"1024" into bool/int,
    # so no custom validators are needed. Blank INI values are dropped by the loader, so
    # model defaults apply rather than empty strings.
    model_config = ConfigDict(frozen=True, extra="forbid")


class GeneralCfg(_Base):
    arch: RequestedArch = "native"
    workspace_dir: str | None = None
    # Storage mode (ADR-0002): where the kernel source tree lives. Auto-detected from the
    # filesystem's case sensitivity, not from the platform -- hence `storage`, not `mac_storage`.
    storage: MacStorage = "auto"
    # The Debug profiles this run builds and boots for. A run-level intent, like `arch`.
    profiles: tuple[str, ...] = ("exploit-dev",)


class SourceCfg(_Base):
    kind: SourceKind = "version"
    value: str = ""


class BuildCfg(_Base):
    compiler: Compiler = "clang"
    toolchain: str = "auto"
    rust: bool = False
    label_suffix: str = ""
    patch_dirs: tuple[str, ...] = ()
    custom_modules: tuple[str, ...] = ()  # validated schema slot; built at boot by ModuleBuildStage.
    extra_fragments: tuple[str, ...] = ()
    ccache: bool = True
    ccache_max_size: str = "5G"

    @field_validator("patch_dirs", "custom_modules", mode="before")
    @classmethod
    def _validate_workspace_relative(cls, v: object) -> object:
        for p in v if isinstance(v, (list, tuple)) else ():
            _reject_unsafe_path(str(p))
        return v

    @field_validator("extra_fragments", mode="before")
    @classmethod
    def _validate_fragments(cls, v: object) -> object:
        for p in v if isinstance(v, (list, tuple)) else ():
            s = str(p)
            _reject_unsafe_path(s)
            if not s.startswith(_FRAGMENTS_PREFIX):
                raise ConfigError(
                    f"extra_fragments path {s!r} must be under '{_FRAGMENTS_PREFIX}'",
                    remedy=f"place fragment files under {_FRAGMENTS_PREFIX}",
                )
        return v


class ForeignCfg(_Base):
    # Presence of `image` selects the foreign (CTF-adopt) path. Path fields accept absolute
    # OR workspace-relative (external read-only artifacts); only '..' traversal is rejected.
    image: str = ""
    vmlinux: str = ""
    initramfs: str = ""
    cmdline: str = ""
    arch: Arch | Literal[""] = ""  # optional override; else auto-detected from the vmlinux ELF
    qemu_extra: tuple[str, ...] = ()
    exploit: str = ""
    # Outbound guest network for a foreign guest (a QEMU device only; not an SSH control
    # transport). Default on: the NIC makes the challenge initramfs's ifup wait succeed and
    # gives the guest outbound network. `net_iface` is the interface name the challenge waits
    # for (read off the guest's "Waiting for interface XXX" console line): ethN uses
    # net.ifnames=0; enp0sN pins the NIC's PCI slot. Never edits the initramfs. See ADR-0017.
    net: bool = True
    net_iface: str = "eth0"

    @field_validator("image", "vmlinux", "initramfs", "exploit", mode="before")
    @classmethod
    def _validate_foreign_path(cls, v: object) -> object:
        if v:
            _reject_traversal(str(v))
        return v


class ExploitCfg(_Base):
    # The exploit auto-compile, shared by the [foreign] repack, `--run` and `--upload`.
    # Extra flags land AFTER the source so libraries resolve in link order
    # (e.g. ["-lpthread", "-D_GNU_SOURCE"]).
    flags: tuple[str, ...] = ()


class RootfsCfg(_Base):
    distribution: str = "bookworm"
    hostname: str = "LIKE-DBG"


class DebuggeeCfg(_Base):
    memory_mib: int = 1024
    smp: int = 1
    accel: Accel = "auto"
    network: Network = "auto"
    # The guest-side gdb *stub* QEMU exposes. The client that attaches to it is [debugger].
    gdbstub: bool = True
    gdbstub_port: int = 1234
    kaslr: bool = False
    smep: bool = True
    smap: bool = True
    kpti: bool = True
    fgkaslr: bool = True  # x86_64-only (out-of-tree/CTF); disabled at runtime with nofgkaslr
    # Tri-state cmdline mitigation hints: None leaves the kernel default untouched (no boot arg emitted),
    # so a default run's cmdline is byte-identical to a build without these knobs set.
    mitigations: bool | None = None
    slab_merge: bool | None = None
    init_on_alloc: bool | None = None
    init_on_free: bool | None = None
    randomize_kstack_offset: bool | None = None
    hardened_usercopy: bool | None = None
    panic: str = "halt"
    capture_console: bool = True
    ssh_port: int = 2222
    share_dir: str = "exploit"
    guest_net: bool = True
    share: bool = True


class DebuggerCfg(_Base):
    ext: Ext = "pwndbg"
    break_on_crash: bool = True
    # FATAL faults (panic/die/oops_enter): armed immediately. SANITIZER breakpoints
    # (kasan_report/ubsan_epilogue): opt-in, EMPTY by default. When set, they are armed only after
    # userspace via gdbcmd's gate. Default empty because on a KASAN kernel with the text_poke false
    # positive kasan_report floods; KASAN is captured from the console into crash.md regardless.
    crash_breakpoints: tuple[str, ...] = ("panic", "die", "oops_enter")
    sanitizer_breakpoints: tuple[str, ...] = ()
    # gdb-native debuginfod: fetch debug info by build-id for stripped/distro/foreign vmlinux.
    # auto = ON for [foreign] runs, OFF for self-built (which always carries its own symtab).
    # Emitted as `set debuginfod enabled on` before the vmlinux load; never `ask` (would block the
    # non-interactive session). See docs/adr/0012-*.
    debuginfod: Debuginfod = "auto"
    debuginfod_urls: str = "https://debuginfod.elfutils.org"


class CacheCfg(_Base):
    max_size: str = ""


class Settings(_Base):
    general: GeneralCfg = GeneralCfg()
    source: SourceCfg = SourceCfg()
    build: BuildCfg = BuildCfg()
    exploit: ExploitCfg = ExploitCfg()
    rootfs: RootfsCfg = RootfsCfg()
    debuggee: DebuggeeCfg = DebuggeeCfg()
    debugger: DebuggerCfg = DebuggerCfg()
    cache: CacheCfg = CacheCfg()
    foreign: ForeignCfg = ForeignCfg()


# ---------------------------------------------------------------------------
# TOML 6-layer loader
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
    "exploit": ExploitCfg,
    "rootfs": RootfsCfg,
    "debuggee": DebuggeeCfg,
    "debugger": DebuggerCfg,
    "cache": CacheCfg,
    "foreign": ForeignCfg,
}

# Section->key->value layer dict.
_Layer = dict[str, dict[str, object]]


def _read_toml(path: Path) -> _Layer:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    # tomllib gives nested dicts already keyed by section.
    return {sec: dict(kv) for sec, kv in data.items() if isinstance(kv, dict)}


def _merge(layers: list[tuple[str, _Layer]]) -> tuple[dict[str, dict[str, object]], dict[tuple[str, str], str]]:
    """Apply ordered (low->high) layers; return merged section dicts + winning-layer provenance."""
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
            # pydantic knows which key failed; say so. "Extra inputs are not permitted" without
            # a key name turns a one-line fix (a typo, or a key that moved between releases)
            # into a hunt through the whole section.
            err = exc.errors()[0]
            key = ".".join(str(part) for part in err["loc"]) or "?"
            raise ConfigError(
                f"invalid [{section}] configuration: {key}: {err['msg']}",
                remedy=f"check `{key}` in the [{section}] section of your TOML config",
            ) from exc
    return Settings(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class ConfigResolution:
    settings: Settings
    provenance: dict[tuple[str, str], str]
    _ordered_layers: tuple[tuple[str, _Layer], ...]  # built-in placeholder excluded; low->high

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
