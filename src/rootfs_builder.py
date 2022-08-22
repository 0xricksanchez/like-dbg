#!/usr/bin/env python3

from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import cfg_setter, adjust_qemu_arch, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class RootFSBuilder(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__()
        cfg_setter(self, ["rootfs_general", "rootfs_builder", "general"])
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.ssh_conn = self.init_ssh()
        self.guarantee_ssh(self.ssh_dir)
        self.fs_name = self.rootfs_base + self.arch + self.rootfs_ftype
        self.rootfs_path = self.rootfs_dir + self.fs_name
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.buildargs = {"USER": self.user}

    def run_container(self):
        try:
            qemu_arch = adjust_qemu_arch(self.arch)
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
        except Exception as e:
            logger.error(f"Oops: {e}")
            exit(-1)
        finally:
            self.stop_container()

    def is_exist(self) -> bool:
        logger.debug(f"Checking for existing rootfs: {self.rootfs_path}")
        if Path(self.rootfs_path).exists():
            return True
        else:
            return False

    def run(self) -> None:
        if self.is_exist() and self.skip_prompts:
            return
        elif self.is_exist() and is_reuse(self.rootfs_path):
            return
        else:
            self.image = self.get_image()
            logger.debug(f"Found rootfs_builder: {self.image}")
            super().run()
