"""tmux session/pane orchestration behind a single, testable object."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Literal

from likedbg.errors import SessionError


def _real_runner(args: list[str]) -> int:
    return subprocess.run(args, check=False).returncode


def _real_query(args: list[str]) -> str:
    return subprocess.run(args, check=False, capture_output=True, text=True).stdout.strip()


class Session:
    def __init__(
        self,
        name: str,
        runner: Callable[[list[str]], int] = _real_runner,
        query: Callable[[list[str]], str] = _real_query,
    ) -> None:
        self.name = name
        self._runner = runner
        self._query = query

    def _tmux(self, *args: str) -> None:
        rc = self._runner(["tmux", *args])
        if rc != 0:
            raise SessionError(
                f"tmux command failed (exit {rc}): {' '.join(args)}",
                remedy="ensure you are running inside a tmux session",
            )

    def select_pane(self, index: int) -> None:
        self._tmux("selectp", "-t", str(index))

    def split(self, direction: Literal["h", "v"], percent: int) -> None:
        self._tmux("splitw", f"-{direction}", "-p", str(percent))

    def send_keys(self, command: str) -> None:
        self._tmux("send-keys", command, "C-m")

    def start(self, name: str) -> None:
        self._tmux("rename-session", name)
        self._tmux("rename-window", name)

    def pane_base_index(self) -> int:
        # tmux pane indices honor the user's `pane-base-index` (commonly 1, not 0).
        # Never assume 0 — query it, falling back to 0 if tmux is unavailable.
        out = self._query(["tmux", "display-message", "-p", "#{pane-base-index}"])
        try:
            return int(out)
        except (TypeError, ValueError):
            return 0

    def open_debug_layout(self) -> tuple[int, int]:
        base = self.pane_base_index()
        self.select_pane(base)
        self.split("h", 66)
        self.split("v", 50)
        self.select_pane(base)
        return (base + 1, base + 2)

    def kill(self) -> None:
        # TODO(plan-3): target panes/session by self.name; name is unused scaffolding for now
        self._tmux("kill-pane", "-a", "-t", str(self.pane_base_index()))
