#!/usr/bin/env python3

from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import cfg_setter, adjust_arch, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class RootFSBuilder(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ["rootfs_general", "rootfs_builder", "general"])
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.ssh_conn = self.init_ssh()
        self.guarantee_ssh(self.ssh_dir)
        self.fs_name = self.rootfs_base + self.arch + self.rootfs_ftype
        self.rootfs_path = self.rootfs_dir + self.fs_name
        self.buildargs = {"USER": self.user}

    def run_container(self):
        qemu_arch = adjust_arch(self.arch)
        command = f"/home/{self.user}/rootfs.sh -n {self.fs_name} -a {qemu_arch} -d {self.distribution} -p {self.packages}"
        container = self.client.containers.run(
            self.image,
            volumes=[f"{Path.cwd() / 'io'}:{self.docker_mnt}"],
            detach=True,
            privileged=True,
            ports={"22/tcp": self.ssh_fwd_port},
            command=command,
        )
        gen = container.logs(stream=True, follow=True)
        [logger.debug(log.strip().decode()) for log in gen]

    def check_existing(self) -> bool:
        logger.debug(f"Checking for existing rootfs: {self.rootfs_path}")
        if Path(self.rootfs_path).exists():
            return is_reuse(self.rootfs_path)
        else:
            return False

    def run(self) -> None:
        if not self.check_existing():
            self.image = self.get_image()
            logger.debug(f"Found rootfs_builder: {self.image}")
            super().run()
