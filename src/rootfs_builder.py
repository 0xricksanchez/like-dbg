#!/usr/bin/env python3

from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_qemu_arch, cfg_setter, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class RootFSBuilder(DockerRunner):
    def __init__(self, partial_run: bool = False, **kwargs) -> None:
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["rootfs_general", "rootfs_builder"], user_cfg)
        self.partial = partial_run
        self.fs_name = self.rootfs_base + self.arch + self.rootfs_ftype
        self.rootfs_path = self.rootfs_dir + self.fs_name
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.script_logging = "set -e" if kwargs.get("log_level", "INFO") == "INFO" else "set -eux"

    def run_container(self) -> None:
        try:
            qemu_arch = adjust_qemu_arch(self.arch)
            command = f"/bin/bash -c '{self.script_logging}; . /home/{self.user}/rootfs.sh -n {self.fs_name} -a {qemu_arch} -d {self.distribution} -p {self.packages} -u {self.user}"
            if self.hostname:
                command += f" -h {self.hostname.strip()}'"
            else:
                command += "'"
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

    def _run(self) -> None:
        self.image = self.get_image()
        logger.debug(f"Found rootfs_builder: {self.image}")
        super().run(check_existing=False)

    def run(self) -> None:
        if self.update_containers:
            super().run(check_existing=False)
            return
        if self.force_rebuild:
            logger.info(f"Force-rebuilding {type(self).__name__}")
            self.image = None
            super().run(check_existing=False)
        else:
            e = self.is_exist()
            if self.partial or not e:
                self._run()
            elif e and self.skip_prompts:
                logger.info(f"Re-using {self.rootfs_path} for file system")
                return
            elif e and is_reuse(self.rootfs_path):
                return
            else:
                self._run()
