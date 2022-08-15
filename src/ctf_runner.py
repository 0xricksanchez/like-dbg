#!/usr/bin/env python3

from pathlib import Path
import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import cfg_setter, tmux, tmux_shell

class CTFRunner(DockerRunner):
    def __init__(self, image: Path, fs: Path) -> None:
        super().__init__()
        self.img = image
        self.fs = fs
        cfg_setter(self, ["debuggee", "debuggee_docker", "general", "kernel_general", "rootfs_general"])

    def run(self):
        if not self.img.exists():
            logger.error(f"Failed to find {self.img}")
            exit(-1)
        if not self.fs.exists():
            logger.error(f"Failed to find {self.fs}")
            exit(-1)
         # TODO
