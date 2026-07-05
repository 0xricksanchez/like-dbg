"""Host-side SSH/scp control seam for the live Debuggee. Subprocess `ssh`/`scp`;
runner/sleep injectable for tests. Host reaches the guest at 127.0.0.1:<ssh_port>."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ServerAlive* bounds an established-then-frozen session: a kernel-killing exploit halts the
# guest (panic trapped under gdb), freezing its TCP stack mid-command. ConnectTimeout only covers
# the connect phase, so without these `run` would block indefinitely and `--run` would never reach
# the capture + crash-analyze step. ~15s (5s x 3) after the guest stops answering keepalives, ssh
# exits non-zero and `--run` proceeds to capture the rc and chain the analyzer. A healthy guest
# answers keepalives in its TCP stack even under load, so normal runs are unaffected.
_SSH_OPTS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "LogLevel=ERROR",
]


@dataclass(frozen=True)
class GuestEndpoint:
    host: str
    port: int
    key: Path
    user: str = "root"


@dataclass(frozen=True)
class GuestResult:
    rc: int
    stdout: str
    stderr: str


def ssh_argv(endpoint: GuestEndpoint, remote_cmd: str) -> list[str]:
    return [
        "ssh",
        "-i",
        str(endpoint.key),
        "-p",
        str(endpoint.port),
        *_SSH_OPTS,
        f"{endpoint.user}@{endpoint.host}",
        remote_cmd,
    ]


def scp_argv(endpoint: GuestEndpoint, local: Path, remote: str) -> list[str]:
    return [
        "scp",
        "-i",
        str(endpoint.key),
        "-P",
        str(endpoint.port),
        *_SSH_OPTS,
        str(local),
        f"{endpoint.user}@{endpoint.host}:{remote}",
    ]


def wait_ready(
    endpoint: GuestEndpoint,
    *,
    timeout: float = 60.0,
    runner: Callable[..., Any] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Poll `ssh … true` until it answers or the timeout elapses. First attempt always runs."""
    deadline = timeout
    while True:
        proc = runner(ssh_argv(endpoint, "true"), capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            return True
        if deadline <= 0:
            return False
        sleep(2.0)
        deadline -= 2.0


def run(endpoint: GuestEndpoint, cmd: str, *, runner: Callable[..., Any] = subprocess.run) -> GuestResult:
    proc = runner(ssh_argv(endpoint, cmd), capture_output=True, text=True, check=False)
    return GuestResult(rc=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")


def push(endpoint: GuestEndpoint, local: Path, remote: str, *, runner: Callable[..., Any] = subprocess.run) -> None:
    runner(scp_argv(endpoint, local, remote), capture_output=True, text=True, check=True)
