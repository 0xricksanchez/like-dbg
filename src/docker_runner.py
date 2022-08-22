#!/usr/bin/env python3

import os
import time
import subprocess as sp
from pathlib import Path

import docker
from fabric import Connection
from loguru import logger

from .misc import is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DOCKER RUNNER                                                                                       |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class DockerRunner:
    def __init__(self, **kwargs) -> None:
        self.skip_prompts = kwargs.get("skip_prompts", False)
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
        switch = False
        tries = 0
        while not switch:
            try:
                self.ssh_conn = Connection(
                    f"{self.user}@localhost:{self.ssh_fwd_port}", connect_kwargs={"key_filename": ".ssh/like.id_rsa"}, connect_timeout=200
                )
            except Exception as e:
                tries += 1
                logger.error(f"Failed to initialize SSH connection to {type(self).__name__}: {e}")
                logger.error("Retrying in 5 seconds...")
                if tries >= 5:
                    logger.error(f"{tries} attempts failed! Exiting...")
                    exit(-1)
                time.sleep(5)
            else:
                logger.debug("Established SSH connection!")
                switch = True

    def build_image_hl(self):
        image = self.client.images.build(path=str(self.dockerfile_ctx), dockerfile=self.dockerfile_path, tag=self.tag)[0]
        return image

    def build_image(self, dockerfile=None, buildargs=None, image_tag=None):
        dockerfile = dockerfile if dockerfile else self.dockerfile
        buildargs = buildargs if buildargs else self.buildargs
        tag = image_tag if image_tag else self.tag
        for log_entry in self.cli.build(path=str(self.dockerfile_ctx), dockerfile=dockerfile, tag=tag, decode=True, buildargs=buildargs):
            v = next(iter(log_entry.values()))
            if isinstance(v, str):
                v = " ".join(v.strip().split())
                if v:
                    logger.debug(v)

    def get_image(self, tag=None):
        to_check = tag if tag else self.tag
        try:
            image = self.client.images.get(to_check)
            return image
        except docker.errors.ImageNotFound:
            return None

    def is_base_image(self) -> bool:
        if self.get_image(tag=self.tag_base_image):
            return True
        else:
            return False

    def build_base_img(self) -> None:
        self.build_image(dockerfile=self.dockerfile_base_img, image_tag=self.tag_base_image)

    def run(self) -> None:
        if not self.image:
            if not self.is_base_image():
                logger.debug("Could not find 'like-dbg'-base image! Building it!")
                self.build_base_img()
            logger.info(f"Building fresh image for {type(self).__name__}")
            self.build_image()
            self.image = self.get_image()
        self.run_container()

    def run_container(self):
        pass

    def stop_container(self) -> None:
        self.container.stop()

    def wait_for_container(self) -> None:
        ret = self.container.wait()
        if ret["StatusCode"] != 0:
            logger.error(f"Failed to run {type(self).__name__}")
            exit(-1)

    def check_existing(self) -> None:
        if self.force_rebuild:
            logger.info(f"Force-rebuilding {type(self).__name__}")
            self.image = None
        else:
            self.image = self.get_image()
            if self.image and self.skip_prompts:
                return
            elif self.image and not is_reuse(self.image.tags[0]):
                self.image = None
