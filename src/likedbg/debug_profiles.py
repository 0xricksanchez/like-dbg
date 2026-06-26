"""Deep module for Debug profiles: loads declarative TOML, resolves the active set into
ordered fragments / expectations / boot args / effective runtime toggles, and verifies the
built .config. TOML defines facts; Python owns compatibility logic."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
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
    debuggee: dict[str, object] = {}


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
