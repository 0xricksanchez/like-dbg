#!/usr/bin/env python3

import subprocess as sp
from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import tmux, tmux_shell, cfg_setter, adjust_qemu_arch


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGEE                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debuggee(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        cfg_setter(self, ["debuggee", "debuggee_docker", "general", "rootfs_general"], exclude_keys=["kernel_root"])
        if kwargs.get("ctf_ctx", False):
            self.kernel = Path(self.docker_mnt) / kwargs.get("ctf_kernel", "")
            self.rootfs = Path(self.docker_mnt) / kwargs.get("ctf_fs", "")
        else:
            self.kernel = Path(self.docker_mnt) / self.kernel_root / "arch" / self.arch / "boot" / "Image"
            self.rootfs = Path(self.docker_mnt) / self.rootfs_dir / (self.rootfs_base + self.arch + self.rootfs_ftype)
        self.qemu_arch = adjust_qemu_arch(self.arch)
        self.cmd = None
        self.buildargs = {"USER": self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def run(self):
        self.check_existing()
        super().run()

    def infer_qemu_fs_mount(self) -> str:
        magic = sp.run(f"file {Path(*self.rootfs.parts[2:])}", shell=True, capture_output=True)
        if b"cpio archive" in magic.stdout:
            return f" -initrd {self.rootfs}"
        elif b"filesystem data" in magic.stdout:
            return f" -drive file={self.rootfs},format=raw"
        else:
            logger.error(f"Unsupported rootfs type: {magic.stdout}")
            exit(-1)

    def run_container(self):
        dcmd = f'docker run -it --rm -v {Path.cwd()}:/io --net="host" like_debuggee '
        self.cmd = f"qemu-system-{self.qemu_arch} -m {self.memory} -smp {self.smp} -kernel {self.kernel}"
        if self.qemu_arch == "aarch64":
            self.cmd += ' -cpu cortex-a72 -machine type=virt -append "console=ttyAMA0 root=/dev/vda'
        elif self.qemu_arch == "x86_64":
            self.cmd += ' -cpu qemu64 -append "console=ttyS0 root=/dev/sda'
        else:
            logger.error(f"Unsupported architecture: {self.qemu_arch}")
            exit(-1)
        self.cmd += " earlyprintk=serial net.ifnames=0"
        if not self.kaslr:
            self.cmd += " nokaslr"
        if not self.smep:
            self.cmd += " nosmep"
        if not self.smap:
            self.cmd += " nosmap"
        if not self.kpti:
            self.cmd += " nopti"
        self.cmd += ' oops=panic panic=-1"'
        self.cmd += self.infer_qemu_fs_mount()
        self.cmd += " -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.kvm and self.qemu_arch == "x86_64":
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        tmux("selectp -t 1")
        runner = f"{dcmd} {self.cmd}"
        tmux_shell(runner)
