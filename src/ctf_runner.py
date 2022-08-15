#!/usr/bin/env python3

from pathlib import Path
import docker
from loguru import logger
import subprocess as sp

from .docker_runner import DockerRunner
from .debuggee import Debuggee
from .debugger import Debugger
from .misc import cfg_setter, tmux, tmux_shell

class MiniDebuggee(DockerRunner):
    def __init__(self, image: Path, fs: Path):
        super().__init__()
        cfg_setter(self, ["general", "debuggee_docker", "debuggee"])
        self.img = image
        self.fs = fs
        self.cmd = None
        self.buildargs = {"USER", self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def infer_qemu_fs_mount(self) -> str:
        magic = sp.run(f"file {self.fs}", shell=True, capture_output=True)
        if b"cpio archive" in magic.stdout:
            return f"-initrd {self.fs}"
        elif b"img" in magic.stdout:
            return f"-drive file={self.fs},format=raw"
        else:
            logger.error(f"Unsupported rootfs type: {magic.stdout}")
            exit(-1)

    def run(self):
        self.check_existing()
        super().run()

    def run_container(self):
        dcmd = f'docker run -it -rm -v {self.ctf_dir}:{self.docker_mnt} --net="host" {self.tag} '
        self.cmd = (
            f"qemu-system-{self.qemu_arch} -m {self.memory} -smp {self.smp} -kernel {self.docker_mnt}/{self.img} "
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
        self.cmd += " oops=panic panic=-1 "
        self.cmd += self.infer_qemu_fs_mount()
        self.cmd += " -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.kvm and self.qemu_arch == "x86_64":
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        tmux("selectp -t 1")
        tmux_shell(f"{dcmd} {self.cmd}")

class MiniDebugger(Debugger):
    pass


class CTFRunner:
    def __init__(self, image: Path, fs: Path) -> None:
        super().__init__()
        self.img = image
        self.fs = fs
        cfg_setter(self, ["debuggee", "debuggee_docker", "general", "kernel_general", "rootfs_general"], cfg_type = "ctf")

    def run(self):
        if not self.img.exists():
            logger.error(f"Failed to find {self.img}")
            exit(-1)
        if not self.fs.exists():
            logger.error(f"Failed to find {self.fs}")
            exit(-1)
        MiniDebuggee(self.img, self.fs).run()
