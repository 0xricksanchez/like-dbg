"""Resolve the Docker client endpoint, honoring the active CLI context (colima)
since docker-py's from_env() ignores it."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from collections.abc import Mapping
from typing import Any


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


def make_client(host: str | None) -> Any:
    import docker

    if host:
        return docker.DockerClient(base_url=host)
    return docker.from_env()
