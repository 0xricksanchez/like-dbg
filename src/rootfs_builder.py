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
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        cfg_setter(self, ["rootfs_general", "rootfs_builder", "general"])
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.fs_name = self.rootfs_base + self.arch + self.rootfs_ftype
        self.rootfs_path = self.rootfs_dir + self.fs_name
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.buildargs = {"USER": self.user}
        self.script_logging = "set -e" if kwargs.get("log_level", "INFO") == "INFO" else "set -eux"

    def run_container(self) -> None:
        try:
            qemu_arch = adjust_qemu_arch(self.arch)
            command = f"/bin/bash -c '{self.script_logging}; . /home/{self.user}/rootfs.sh -n {self.fs_name} -a {qemu_arch} -d {self.distribution} -p {self.packages} -u {self.user}'"
            self.container = self.client.containers.run(
                self.image,
                volumes={f"{Path.cwd() / 'io'}": {"bind": f"{self.docker_mnt}", "mode": "rw"}},
                detach=True,
                privileged=True,
                remove=True,
                command=command,
            )
            gen = self.container.logs(stream=True, follow=True)
            [logger.info(log.strip().decode()) for log in gen]
            self.wait_for_container()
        except Exception as e:
            logger.critical(f"Oops: {e}")
            exit(-1)

    def is_exist(self) -> bool:
        logger.debug(f"Checking for existing rootfs: {self.rootfs_path}")
        if Path(self.rootfs_path).exists():
            return True
        else:
            return False

    def run(self) -> None:
        if self.force_rebuild:
            logger.info(f"Force-rebuilding {type(self).__name__}")
            self.image = None
            super().run()
        else:
            e = self.is_exist()
            if e and self.skip_prompts:
                logger.info(f"Re-using {self.rootfs_path} for file system")
                return
            elif e and is_reuse(self.rootfs_path):
                return
            else:
                self.image = self.get_image()
                logger.debug(f"Found rootfs_builder: {self.image}")
                super().run()
