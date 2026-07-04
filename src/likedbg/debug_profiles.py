"""Deep module for Debug profiles: loads declarative TOML, resolves the active set into
ordered fragments / expectations / boot args / effective runtime toggles, and verifies the
built .config. TOML defines facts; Python owns compatibility logic."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError

from likedbg.config import _FRAGMENTS_PREFIX
from likedbg.config import LAYER_CLI
from likedbg.config import LAYER_LOCAL
from likedbg.config import LAYER_PROFILE
from likedbg.config import LAYER_SCENARIO
from likedbg.config import ConfigResolution
from likedbg.config import DebuggeeCfg
from likedbg.config import Settings
from likedbg.config import _reject_unsafe_path
from likedbg.errors import ConfigError
from likedbg.host_profile import HostProfile

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class _PBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Expect(_PBase):
    symbol: str
    value: Literal["y", "m", "n"]  # "n" → "# CONFIG_FOO is not set"
    severity: Literal["hard", "soft"]
    arch: tuple[str, ...] | None = None
    kernel_min: str | None = None
    kernel_max: str | None = None


ConfigExpectation = Expect


class BootArg(_PBase):
    value: str
    arch: tuple[str, ...] | None = None
    kernel_min: str | None = None
    kernel_max: str | None = None
    profiles: tuple[str, ...] | None = None


class ProfileWarning(_PBase):
    message: str
    arch: tuple[str, ...] | None = None
    accel: tuple[str, ...] | None = None
    host_os: tuple[str, ...] | None = None
    profiles: tuple[str, ...] | None = None


class _RuntimeDefaults(_PBase):
    debuggee: dict[str, object] = Field(default_factory=dict)


class ProfileDef(_PBase):
    name: str
    kind: Literal["base", "addon"]
    description: str
    implies: tuple[str, ...] = ()
    fragments: tuple[str, ...] = ()
    boot_arg: tuple[BootArg, ...] = ()
    runtime_defaults: _RuntimeDefaults = _RuntimeDefaults()
    warning: tuple[ProfileWarning, ...] = ()
    expect: tuple[Expect, ...] = ()


def parse_profile_names(raw: str | Sequence[str]) -> tuple[str, ...]:
    names = [p.strip() for p in raw.split(",")] if isinstance(raw, str) else [str(p).strip() for p in raw]
    names = [n for n in names if n]
    if not names:
        raise ConfigError("no debug profile specified", remedy="pass at least one profile name")
    for n in names:
        if not _NAME_RE.match(n):
            raise ConfigError(
                f"invalid debug profile name {n!r}",
                remedy="profile names are lowercase and match [a-z0-9][a-z0-9._-]*",
            )
    # de-duplicate, preserve first-seen order
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(n, None)
    return tuple(seen)


def load_profiles(workspace: Path) -> dict[str, ProfileDef]:
    pdir = workspace / "configs" / "profiles"
    registry: dict[str, ProfileDef] = {}
    for path in sorted(pdir.glob("*.toml")):
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        try:
            pdef = ProfileDef(**data)
        except ValidationError as exc:
            raise ConfigError(
                f"invalid profile {path.name}: {exc.errors()[0]['msg']}",
                remedy=f"fix {path}",
            ) from exc
        for frag in pdef.fragments:
            _reject_unsafe_path(frag)
            if not frag.startswith(_FRAGMENTS_PREFIX):
                raise ConfigError(
                    f"profile {path.stem!r}: fragment {frag!r} must be under '{_FRAGMENTS_PREFIX}'",
                    remedy=f"place fragment files under {_FRAGMENTS_PREFIX}",
                )
        if pdef.name != path.stem:
            raise ConfigError(
                f"profile filename/name mismatch: {path.name} declares name={pdef.name!r}",
                remedy="rename the file or the name field so they match",
            )
        if pdef.name in registry:
            raise ConfigError(f"duplicate profile name {pdef.name!r}", remedy=f"remove the duplicate under {pdir}")
        registry[pdef.name] = pdef
    return registry


@dataclass(frozen=True)
class ResolvedDebugProfiles:
    names: tuple[str, ...]
    base: str
    expected_config: tuple[Expect, ...]
    future_breakpoint_groups: tuple[str, ...]


@dataclass(frozen=True)
class ProfileVerification:
    satisfied: tuple[Expect, ...]
    missing_hard: tuple[Expect, ...]
    missing_soft: tuple[Expect, ...]
    warnings: tuple[str, ...]


def version_tuple(release: str) -> tuple[int, ...]:
    nums: list[int] = []
    for part in release.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums)


def parse_kernel_release(makefile_text: str) -> str:
    fields = {"VERSION": "", "PATCHLEVEL": "", "SUBLEVEL": "", "EXTRAVERSION": ""}
    for line in makefile_text.splitlines():
        for key in fields:
            m = re.match(rf"^{key}\s*=\s*(.*)$", line.strip())
            if m:
                fields[key] = m.group(1).strip()
    base = ".".join(v for v in (fields["VERSION"], fields["PATCHLEVEL"], fields["SUBLEVEL"]) if v)
    return base + fields["EXTRAVERSION"]


def _config_has(config_text: str, symbol: str, value: str) -> bool:
    if value == "n":
        return f"# {symbol} is not set" in config_text or not re.search(rf"^{re.escape(symbol)}=", config_text, re.M)
    return bool(re.search(rf"^{re.escape(symbol)}={value}$", config_text, re.M))


def _expect_applies(e: Expect, *, target_arch: str, kernel_release: str | None) -> bool:
    if e.arch is not None and target_arch not in e.arch:
        return False
    if kernel_release is not None:
        kv = version_tuple(kernel_release)
        if e.kernel_min is not None and kv < version_tuple(e.kernel_min):
            return False
        if e.kernel_max is not None and kv > version_tuple(e.kernel_max):
            return False
    return True


def verify_config(
    config_text: str, resolved: ResolvedDebugProfiles, *, target_arch: str, kernel_release: str | None
) -> ProfileVerification:
    # Normalise CRLF -> LF: container reads of .config run over a pseudo-terminal (tty=True)
    # and come back with \r\n, which would break the anchored ``^SYMBOL=value$`` matches below
    # (a false "unmet" for every =y/=m expectation, including hard ones).
    config_text = config_text.replace("\r\n", "\n")
    satisfied: list[Expect] = []
    missing_hard: list[Expect] = []
    missing_soft: list[Expect] = []
    warnings: list[str] = []
    for e in resolved.expected_config:
        if not _expect_applies(e, target_arch=target_arch, kernel_release=kernel_release):
            continue
        if _config_has(config_text, e.symbol, e.value):
            satisfied.append(e)
        elif e.severity == "hard":
            missing_hard.append(e)
        else:
            missing_soft.append(e)
            warnings.append(f"soft expectation unmet: {e.symbol} expected {e.value}")
    return ProfileVerification(
        satisfied=tuple(satisfied),
        missing_hard=tuple(missing_hard),
        missing_soft=tuple(missing_soft),
        warnings=tuple(warnings),
    )


_EXPLICIT_LAYERS: frozenset[str] = frozenset({LAYER_LOCAL, LAYER_SCENARIO, LAYER_CLI})
# Runtime toggle → build symbol it requires to be enable-able.
_TOGGLE_REQUIRES: dict[str, str] = {"kaslr": "CONFIG_RANDOMIZE_BASE"}


@dataclass(frozen=True)
class RunResolution:
    requested_settings: Settings
    provenance: dict[tuple[str, str], str]
    target_arch: str
    profiles: ResolvedDebugProfiles
    fragments: tuple[str, ...]
    effective_debuggee: DebuggeeCfg
    runtime_defaults: dict[str, str]
    runtime_overrides: tuple[str, ...]
    extra_boot_args: tuple[str, ...]
    profile_warnings: tuple[str, ...]
    runtime_notes: tuple[str, ...]
    implied_by: dict[str, tuple[str, ...]]


def _expand(
    profile_names: tuple[str, ...], registry: dict[str, ProfileDef]
) -> tuple[list[str], str, dict[str, list[str]]]:
    """Return (ordered resolved names, base, implied_by) — base first, implied add-ons, explicit add-ons."""
    for n in profile_names:
        if n not in registry:
            choices = ", ".join(sorted(registry))
            raise ConfigError(f"unknown debug profile {n!r}", remedy=f"choose one of {choices}")
    requested_bases = [n for n in profile_names if registry[n].kind == "base"]
    if len(requested_bases) > 1:
        raise ConfigError(
            f"multiple base profiles requested: {', '.join(requested_bases)}",
            remedy="choose exactly one base profile (e.g. exploit-dev OR hardened)",
        )
    base = requested_bases[0] if requested_bases else "exploit-dev"
    if base not in registry:
        raise ConfigError(f"base profile {base!r} not found", remedy="add configs/profiles/exploit-dev.toml")
    explicit_addons = [n for n in profile_names if registry[n].kind == "addon"]
    implied_by: dict[str, list[str]] = {}
    implied: list[str] = []
    for n in explicit_addons:
        for imp in registry[n].implies:
            if imp not in registry:
                raise ConfigError(
                    f"profile {n!r} implies unknown profile {imp!r}",
                    remedy=f"choose one of {', '.join(sorted(registry))}",
                )
            if registry[imp].kind != "addon":
                continue
            implied_by.setdefault(imp, []).append(n)
            if imp not in implied and imp not in explicit_addons:
                implied.append(imp)
    ordered = [base, *implied, *[a for a in explicit_addons if a not in implied]]
    # de-dupe preserving order
    seen: dict[str, None] = {}
    for n in ordered:
        seen.setdefault(n, None)
    return list(seen), base, implied_by


def _selectors_match(
    *,
    arch: tuple[str, ...] | None = None,
    accel: tuple[str, ...] | None = None,
    host_os: tuple[str, ...] | None = None,
    profiles: tuple[str, ...] | None = None,
    active: set[str],
    host: HostProfile,
) -> bool:
    if arch is not None and host.target_arch not in arch:
        return False
    if accel is not None and host.accel not in accel:
        return False
    if host_os is not None and host.os not in host_os:
        return False
    if profiles is not None and not set(profiles).issubset(active):
        return False
    return True


def resolve_run(
    *, profile_names: tuple[str, ...], config: ConfigResolution, host: HostProfile, workspace: Path
) -> RunResolution:
    registry = load_profiles(workspace)
    ordered, base, implied_by_lists = _expand(profile_names, registry)
    active = set(ordered)
    defs = [registry[n] for n in ordered]

    fragments = tuple(f for d in defs for f in d.fragments)
    expectations = tuple(e for d in defs for e in d.expect)

    # Profile runtime defaults (layer 4) — later profiles win on conflict.
    runtime_defaults: dict[str, str] = {}
    for d in defs:
        for k, v in d.runtime_defaults.debuggee.items():
            runtime_defaults[k] = "true" if v is True else "false" if v is False else str(v)

    effective_debuggee, eff_prov = config.effective_debuggee(runtime_defaults)

    warnings: list[str] = [
        w.message
        for d in defs
        for w in d.warning
        if _selectors_match(
            arch=w.arch, accel=w.accel, host_os=w.host_os, profiles=w.profiles, active=active, host=host
        )
    ]

    boot_args: list[str] = []
    runtime_notes: list[str] = []
    for d in defs:
        for ba in d.boot_arg:
            if ba.kernel_min is not None or ba.kernel_max is not None:
                runtime_notes.append(
                    f"deferred version-gated boot arg {ba.value!r} (B1 does not evaluate kernel_min/max)"
                )
                continue
            if _selectors_match(arch=ba.arch, profiles=ba.profiles, active=active, host=host):
                boot_args.append(ba.value)

    # Compatibility: resolution-time contradictions (Q12).
    overrides: list[str] = []
    for toggle, symbol in _TOGGLE_REQUIRES.items():
        wants_on = bool(getattr(effective_debuggee, toggle))
        forbidden_hard = any(
            e.symbol == symbol
            and e.value == "n"
            and e.severity == "hard"
            and _expect_applies(e, target_arch=host.target_arch, kernel_release=None)
            for e in expectations
        )
        prov = eff_prov.get(("debuggee", toggle))
        explicit = prov in _EXPLICIT_LAYERS
        if wants_on and forbidden_hard:
            # Only EXPLICIT (user/scenario/CLI) requests are hard errors (Q12). When the toggle is on
            # via a profile default with no build symbol, the runtime kaslr boot arg is a harmless no-op,
            # so we silently pass — this is intentional, not a missing else.
            if explicit:
                raise ConfigError(
                    f"[debuggee] {toggle}=on is impossible: active profiles build {symbol} disabled",
                    remedy="remove the explicit toggle, or switch to a base profile that builds it in (e.g. hardened)",
                )
        if not wants_on and prov == LAYER_PROFILE:
            overrides.append(f"runtime override: {toggle} off → adds nokaslr (profile default was on)")

    resolved = ResolvedDebugProfiles(
        names=tuple(ordered), base=base, expected_config=expectations, future_breakpoint_groups=()
    )
    return RunResolution(
        requested_settings=config.settings,
        provenance=eff_prov,
        target_arch=host.target_arch,
        profiles=resolved,
        fragments=fragments,
        effective_debuggee=effective_debuggee,
        runtime_defaults=runtime_defaults,
        runtime_overrides=tuple(overrides),
        extra_boot_args=tuple(boot_args),
        profile_warnings=tuple(warnings),
        runtime_notes=tuple(runtime_notes),
        implied_by={k: tuple(v) for k, v in implied_by_lists.items()},
    )
