#!/usr/bin/env python3

import os
from pathlib import Path

import docker
from fabric import Connection
from loguru import logger

from .misc import is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DOCKER RUNNER                                                                                       |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class DockerRunner:
    def __init__(self) -> None:
        self.dockerfile_ctx = Path.cwd()
        self.client = docker.from_env()
        self.ssh_conn = None
        self.image = None
        self.tag = None
        self.user = None
        self.ssh_fwd_port = None
        self.container = None

    def guarantee_ssh(self, ssh_dir: Path) -> None:
        if Path(ssh_dir).exists() and os.listdir(ssh_dir):
            logger.debug(f"Reusing local ssh keys from {ssh_dir}...")
        else:
            logger.debug("Generating new ssh key pair...")
            if not Path(ssh_dir).exists():
                Path(ssh_dir).mkdir()
            sp.run(f'ssh-keygen -f {Path(ssh_dir) / "like.id_rsa"} -t rsa -N ""', shell=True)

    def init_ssh(self):
        # TODO remove hardcoded values in favor of a config
        self.ssh_conn = Connection(f"{self.user}@localhost:{self.ssh_fwd_port}",
                                   connect_kwargs={"key_filename": ".ssh/like.id_rsa"}
                                   )

    def build_image_hl(self):
        image = self.client.images.build(
            path=str(self.dockerfile_ctx),
            dockerfile=self.dockerfile_path,
            tag=self.tag
        )[0]
        return image

    def build_image(self):
        for log_entry in self.cli.build(
                path=str(self.dockerfile_ctx),
                dockerfile=self.dockerfile,
                tag=self.tag,
                decode=True,
                buildargs=self.buildargs
        ):
            v = next(iter(log_entry.values()))
            if isinstance(v, str):
                v = ' '.join(v.strip().split())
                if v:
                    logger.debug(v)

    def get_image(self):
        try:
            image = self.client.images.get(self.tag)
            return image
        except docker.errors.ImageNotFound:
            return None

    def run(self):
        if not self.image:
            logger.info(f"Building fresh image for {type(self).__name__}")
            self.build_image()
            self.image = self.get_image()
        self.run_container()

    def run_container(self):
        pass

    def stop_container(self):
        self.container.stop()

    def check_existing(self) -> None:
        self.image = self.get_image()
        if self.image and not is_reuse(self.image.tags[0]):
            self.image = None
