"""Resolve the Docker client endpoint, honoring the active CLI context (colima)
since docker-py's from_env() ignores it."""

from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from collections.abc import Mapping
from typing import Any

from likedbg.errors import ContainerError


def _read_active_context_host() -> str | None:
    try:
        out = subprocess.run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    host = out.stdout.strip()
    return host or None


def resolve_docker_host(
    *, env: Mapping[str, str], read_context_host: Callable[[], str | None] = _read_active_context_host
) -> str | None:
    if env.get("DOCKER_HOST"):
        return env["DOCKER_HOST"]
    return read_context_host()


def daemon_remedy(os_name: str) -> str:
    """How to get a daemon answering on this host.

    Engine-agnostic on macOS for the same reason `bootstrap._docker_prereq` is: LIKE-DBG talks to
    whatever the active Docker CLI context points at, so Docker Desktop, colima and OrbStack are
    equally fine and naming only one sends half the users the wrong way.
    """
    if os_name == "darwin":
        return "start a Docker engine (launch Docker Desktop or OrbStack, or run `colima start`), then retry"
    return (
        "start the Docker daemon (`sudo systemctl start docker`) and check you are in the `docker` "
        "group; `just check` reports every prerequisite"
    )


def make_client(host: str | None, *, os_name: str | None = None) -> Any:
    import docker
    from docker.errors import DockerException

    try:
        return docker.DockerClient(base_url=host) if host else docker.from_env()
    except DockerException as exc:
        # docker-py wraps every connect failure (missing socket, refused, TLS, permission) in
        # DockerException while probing the server API version, so this one clause covers them all.
        where = f" at {host}" if host else ""
        raise ContainerError(
            f"cannot reach the Docker daemon{where}: {exc}",
            remedy=daemon_remedy(platform.system().lower() if os_name is None else os_name),
        ) from exc
