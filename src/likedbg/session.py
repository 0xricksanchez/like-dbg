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


def _real_checked_query(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(args, check=False, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


class Session:
    def __init__(
        self,
        name: str,
        runner: Callable[[list[str]], int] = _real_runner,
        query: Callable[[list[str]], str] = _real_query,
        checked_query: Callable[[list[str]], tuple[int, str]] = _real_checked_query,
    ) -> None:
        self.name = name
        self._runner = runner
        self._query = query
        self._checked_query = checked_query

    def _tmux(self, *args: str) -> None:
        rc = self._runner(["tmux", *args])
        if rc != 0:
            raise SessionError(
                f"tmux command failed (exit {rc}): {' '.join(args)}",
                remedy="ensure you are running inside a tmux session",
            )

    def _tmux_query(self, *args: str) -> str:
        rc, out = self._checked_query(["tmux", *args])
        if rc != 0:
            raise SessionError(
                f"tmux command failed (exit {rc}): {' '.join(args)}",
                remedy="ensure you are running inside a tmux session",
            )
        return out

    def select_pane(self, target: int | str) -> None:
        self._tmux("selectp", "-t", str(target))

    def start(self, name: str) -> None:
        self._tmux("rename-session", name)
        self._tmux("rename-window", name)

    def current_pane_id(self) -> str:
        return self._query(["tmux", "display-message", "-p", "#{pane_id}"])

    def pane_base_index(self) -> int:
        # tmux pane indices honor the user's `pane-base-index` (commonly 1, not 0).
        # Never assume 0 — query it, falling back to 0 if tmux is unavailable.
        out = self._query(["tmux", "display-message", "-p", "#{pane-base-index}"])
        try:
            return int(out)
        except (TypeError, ValueError):
            return 0

    def run_in_new_pane(
        self,
        *,
        target: int | str,
        direction: Literal["h", "v"],
        percent: int,
        cmd: str,
    ) -> str:
        wrapped_cmd = f"tmux set-option -p remain-on-exit on; exec {cmd}"
        pane = self._tmux_query(
            "split-window",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            f"-{direction}",
            "-p",
            str(percent),
            "-t",
            str(target),
            wrapped_cmd,
        )
        return pane

    def respawn_pane(self, *, pane: str, cmd: str) -> None:
        self.set_remain_on_exit(pane)
        self._tmux("respawn-pane", "-k", "-t", pane, cmd)

    def pane_exists(self, pane: str) -> bool:
        return self._runner(["tmux", "display-message", "-p", "-t", pane, "#{pane_id}"]) == 0

    def get_option(self, name: str) -> str:
        return self._query(["tmux", "show-option", "-qv", name])

    def set_option(self, name: str, value: str) -> None:
        self._tmux("set-option", name, value)

    def unset_option(self, name: str) -> None:
        self._tmux("set-option", "-u", name)

    def display_message(self, message: str) -> None:
        self._tmux("display-message", message)

    def set_remain_on_exit(self, pane: str) -> None:
        self._tmux("set-option", "-p", "-t", pane, "remain-on-exit", "on")

    def kill(self) -> None:
        # TODO(plan-3): target panes/session by self.name; name is unused scaffolding for now
        self._tmux("kill-pane", "-a", "-t", str(self.pane_base_index()))
