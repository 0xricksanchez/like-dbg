#!/usr/bin/env python3

from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import tmux, tmux_shell, cfg_setter, adjust_qemu_arch


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGEE                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debuggee(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ["debuggee", "debuggee_docker", "general", "kernel_general", "rootfs_general"])
        self.img = Path(self.docker_mnt) / self.rootfs_dir / (self.rootfs_base + self.arch + self.rootfs_ftype)
        self.qemu_arch = adjust_qemu_arch(self.arch)
        self.cmd = None
        self.buildargs = {"USER": self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def run(self):
        self.check_existing()
        super().run()

    def run_container(self):
        dcmd = 'docker run -it --rm -v /home/raven/Git/like-dbg/:/io --net="host" like_debuggee '
        self.cmd = (
            f"qemu-system-{self.qemu_arch} -m {self.memory} -smp {self.smp} -kernel {self.docker_mnt}/{self.kernel_root}/arch/{self.arch}/boot/Image "
        )
        if self.qemu_arch == "aarch64":
            self.cmd += '-cpu cortex-a72 -machine type=virt -append "console=ttyAMA0 root=/dev/vda '
        elif self.qemu_arch == "x86_64":
            self.cmd += ' -append "console=ttyS0 root=/dev/sda '
        else:
            logger.error(f"Unsupported architecture: {self.qemu_arch}")
            exit(-1)
        self.cmd += " earlyprintk=serial net.ifnames=0 "
        if not self.kaslr:
            self.cmd += " nokaslr"
        if not self.smep:
            self.cmd += " nosmep"
        if not self.smap:
            self.cmd += " nosmap"
        if not self.kpti:
            self.cmd += " nopti"
        self.cmd += f' oops=panic panic=-1" -drive file={self.img},format=raw -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid'
        if self.kvm and self.qemu_arch == "x86_64":
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        tmux("selectp -t 1")
        tmux_shell(f"{dcmd} {self.cmd}")
