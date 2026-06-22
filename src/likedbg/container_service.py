"""Thin, runtime-agnostic wrapper over docker-py used by the pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import docker.errors

from likedbg.errors import ContainerError


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    output: str


class ContainerService:
    def __init__(self, client: Any, *, docker_mnt: str = "/io") -> None:
        self._client = client
        self.docker_mnt = docker_mnt

    def image_exists(self, tag: str) -> bool:
        try:
            self._client.images.get(tag)
        except docker.errors.ImageNotFound:
            return False
        return True

    def build_image(self, dockerfile: str, tag: str, buildargs: dict[str, str], *, nocache: bool = False) -> None:
        try:
            self._client.images.build(
                path=".", dockerfile=dockerfile, tag=tag, buildargs=buildargs, nocache=nocache, rm=True
            )
        except docker.errors.APIError as exc:
            raise ContainerError(
                f"failed to build image {tag} from {dockerfile}: {exc}",
                remedy="check the Dockerfile and that the container runtime is running",
            ) from exc

    def run_detached(self, image: str, **kwargs: Any) -> Any:
        return self._client.containers.run(image, **kwargs)

    def exec(self, container: Any, cmd: str, *, workdir: str | None = None) -> ExecResult:
        result = container.exec_run(cmd, workdir=workdir)
        output = result.output.decode() if isinstance(result.output, bytes) else str(result.output)
        if result.exit_code != 0:
            raise ContainerError(
                f"command failed (exit {result.exit_code}): {cmd}\n{output}",
                remedy="inspect the command output above",
            )
        return ExecResult(exit_code=result.exit_code, output=output)

    def stop(self, container: Any) -> None:
        container.stop()
