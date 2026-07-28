"""Host port selection for a boot.

Two guests cannot both hold `gdbstub_port` or the SSH `hostfwd` port, so a second concurrent
session needs different ones. The rule is deliberately asymmetric, because the two cases mean
different things:

- A port you never chose (the pydantic default, or the `gdbstub_port = 1234` line every shipped
  `configs/default.toml` carries) is a placeholder. Moving it is a convenience, and it is
  announced, never silent.
- A port you *did* choose -- in a scenario, `local.toml`, a profile, or on the command line -- is
  an instruction. Quietly booting on a different one would break the thing you set it for (a
  fixed gdb target, a port-forward, a script). A busy pinned port is an error you can act on.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass

from likedbg.config import LAYER_BUILTIN
from likedbg.config import LAYER_DEFAULT
from likedbg.config import DebuggeeCfg
from likedbg.errors import ConfigError

# Only these two layers mean "nobody expressed an opinion". Anything higher -- profile, local,
# scenario, CLI -- is a deliberate choice and is honoured exactly or not at all.
_UNCHOSEN_LAYERS = frozenset({LAYER_BUILTIN, LAYER_DEFAULT})

_SEARCH_SPAN = 64  # ports scanned upward from the requested one before giving up


def port_is_free(port: int) -> bool:
    """Whether `port` can be bound on this host, right now.

    Binds INADDR_ANY deliberately: that conflicts with a listener on *any* single interface, so
    it is the stricter test. QEMU's hostfwd binds 127.0.0.1 while a published container port
    binds 0.0.0.0, and both must be caught.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("", port))
        except OSError:
            return False
    return True


@dataclass(frozen=True)
class PortPlan:
    debuggee: DebuggeeCfg
    notes: tuple[str, ...]  # human-readable, one per port that moved


def _pin_or_move(
    label: str,
    requested: int,
    *,
    pinned: bool,
    is_free: Callable[[int], bool],
    reserved: set[int],
) -> tuple[int, str | None]:
    if requested not in reserved and is_free(requested):
        return requested, None
    if pinned:
        raise ConfigError(
            f"[debuggee] {label} {requested} is already in use",
            remedy=f"stop whatever holds port {requested}, or set a different [debuggee] {label}",
        )
    for candidate in range(requested + 1, requested + 1 + _SEARCH_SPAN):
        if candidate not in reserved and is_free(candidate):
            return candidate, f"{label} {requested} was busy; using {candidate}"
    raise ConfigError(
        f"no free port for [debuggee] {label} near {requested}",
        remedy=f"free a port in {requested}-{requested + _SEARCH_SPAN}, or set [debuggee] {label} explicitly",
    )


def resolve_ports(
    eff: DebuggeeCfg,
    provenance: Mapping[tuple[str, str], str],
    *,
    is_free: Callable[[int], bool] = port_is_free,
) -> PortPlan:
    """Pick the host ports this boot will actually use.

    Only ports this boot will really bind are considered: `gdbstub_port` when the stub is enabled,
    `ssh_port` when the guest has the SSH control transport (a foreign guest has neither, so it
    contends for nothing).
    """
    reserved: set[int] = set()
    updates: dict[str, int] = {}
    notes: list[str] = []
    wanted = []
    if eff.gdbstub:
        wanted.append("gdbstub_port")
    if eff.guest_net:
        wanted.append("ssh_port")
    for label in wanted:
        requested = int(getattr(eff, label))
        pinned = provenance.get(("debuggee", label), LAYER_BUILTIN) not in _UNCHOSEN_LAYERS
        chosen, note = _pin_or_move(label, requested, pinned=pinned, is_free=is_free, reserved=reserved)
        reserved.add(chosen)
        if chosen != requested:
            updates[label] = chosen
        if note:
            notes.append(note)
    return PortPlan(debuggee=eff.model_copy(update=updates) if updates else eff, notes=tuple(notes))
