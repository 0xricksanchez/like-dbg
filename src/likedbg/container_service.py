"""Thin, runtime-agnostic wrapper over docker-py used by the pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import docker.errors
from loguru import logger

from likedbg.errors import ContainerError


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    output: str


def _tail(text: str, n: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:])


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

    def build_image(
        self,
        dockerfile: str,
        tag: str,
        buildargs: dict[str, str],
        *,
        nocache: bool = False,
        labels: dict[str, str] | None = None,
    ) -> None:
        try:
            self._client.images.build(
                path=".", dockerfile=dockerfile, tag=tag, buildargs=buildargs, nocache=nocache, rm=True, labels=labels
            )
        except docker.errors.APIError as exc:
            raise ContainerError(
                f"failed to build image {tag} from {dockerfile}: {exc}",
                remedy="check the Dockerfile and that the container runtime is running",
            ) from exc

    def run_detached(self, image: str, *, auto_remove: bool = True, **kwargs: Any) -> Any:
        """Run a short-lived utility container detached and return its handle.

        Intended for ephemeral helpers that do work then stop (unpack/build/rootfs/export/
        adopt/cache-removal). ``auto_remove=True`` (default) lets the daemon delete the
        container once it stops, so stopped containers do not accumulate. Long-lived guests
        (the Debuggee and Debugger) are launched as tmux ``docker run`` pane commands, NOT
        through this method.
        """
        return self._client.containers.run(image, auto_remove=auto_remove, **kwargs)

    def exec(self, container: Any, cmd: str, *, workdir: str | None = None) -> ExecResult:
        # Stream via the low-level API with tty=True so output is a single clean merged stream
        # (no stdout/stderr multiplex frames) and every line is logged live at DEBUG.
        api = self._client.api
        exec_id = api.exec_create(container.id, ["/bin/sh", "-c", cmd], workdir=workdir, tty=True)["Id"]
        chunks: list[str] = []
        for chunk in api.exec_start(exec_id, tty=True, stream=True):
            text = chunk.decode(errors="replace") if isinstance(chunk, bytes) else str(chunk)
            chunks.append(text)
            for line in text.splitlines():
                logger.debug(line)
        output = "".join(chunks)
        exit_code = api.exec_inspect(exec_id)["ExitCode"]
        if exit_code != 0:
            raise ContainerError(
                f"command failed (exit {exit_code}): {cmd}\n{_tail(output)}",
                remedy="inspect the output above / artifacts/logs/latest.log",
            )
        return ExecResult(exit_code=exit_code, output=output)

    def image_labels(self, tag: str) -> dict[str, str]:
        try:
            image = self._client.images.get(tag)
        except docker.errors.ImageNotFound as exc:
            raise ContainerError(
                f"image not found: {tag}", remedy="build it first (`start_kgdb --build-images`)"
            ) from exc
        return image.labels or {}

    def stop(self, container: Any) -> None:
        container.stop()

    def remove_volume(self, name: str) -> None:
        """Delete a named Docker volume if it exists (idempotent). Used by --clean-all to reset
        the persistent exploit-compile (zig) cache."""
        try:
            self._client.volumes.get(name).remove(force=True)
        except docker.errors.NotFound:
            pass
