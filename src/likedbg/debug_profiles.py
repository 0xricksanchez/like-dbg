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

from likedbg.errors import ConfigError

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
