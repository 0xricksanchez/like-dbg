"""Reading a Run artifact's state back off disk, and deciding what to say when a run cannot
serve the command being asked of it.

Deliberately separate from `run_artifacts` (which *writes* a run) so the read side stays a leaf:
`--run`, `--insmod`, `--rmmod` and `--upload` all reach for it, and none of them should drag the
recorder -- or its config/profile imports -- along.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from likedbg.errors import LikeDbgError

# cmd_foreign labels its runs `foreign-<scenario>`; a built run's label is `linux-<version>-<hash>`.
# That prefix is the only in-artifact signal that a run adopted its kernel rather than building it.
_FOREIGN_LABEL_PREFIX = "foreign-"


def read_run_state(run_dir: Path, name: str, *, error: type[LikeDbgError]) -> dict[str, Any]:
    """Parse `<run_dir>/<name>` (run.json / host.json) as a JSON object, or raise `error`.

    A run directory whose JSON is absent or truncated is a real state, not a can't-happen: a
    RunRecorder interrupted between `mkdir` and its first write leaves exactly that. It must not
    reach the user as a traceback -- every other failure in this tool carries a remedy.
    """
    path = run_dir / name
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise error(
            f"run artifact not readable: {path}",
            remedy="pick another --run-id, or start a fresh session",
        ) from exc
    except ValueError as exc:
        raise error(
            f"run artifact is corrupt: {path}",
            remedy="this run was interrupted while being recorded; start a fresh session",
        ) from exc
    if not isinstance(data, dict):
        raise error(
            f"run artifact is not a JSON object: {path}",
            remedy="this run was interrupted while being recorded; start a fresh session",
        )
    return data


def is_foreign_run(run_json: dict[str, Any]) -> bool:
    """Whether this run adopted its kernel (a `[foreign]` scenario) rather than building one."""
    return str(run_json.get("build_label", "")).startswith(_FOREIGN_LABEL_PREFIX)


def guest_endpoint(
    run_json: dict[str, Any],
    *,
    error: type[LikeDbgError],
    foreign_remedy: str,
) -> dict[str, Any]:
    """The run's SSH/9p control endpoint, or a refusal that fits how the run was actually booted.

    A foreign run has no control transport *by design*: cmd_foreign forces `guest_net=False`
    because an adopted challenge ships no sshd and no key. Telling that operator to
    "boot with guest_net enabled" sends them after something the design will not give them, so
    the caller supplies the remedy that is true for its own command.
    """
    guest = run_json.get("guest")
    if guest:
        return dict(guest)
    if is_foreign_run(run_json):
        raise error(
            "this run adopted a foreign kernel, which has no SSH control transport",
            remedy=foreign_remedy,
        )
    raise error("this run has no guest endpoint", remedy="boot with guest_net enabled")
