#!/usr/bin/env python3

import subprocess as sp
from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_qemu_arch, cfg_setter, tmux, tmux_shell


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGEE                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debuggee(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["general", "debuggee", "debuggee_docker", "rootfs_general"], user_cfg, exclude_keys=["kernel_root"])
        if self.ctf:
            self.ctf_mount = kwargs.get("ctf_mount")
            self.kernel = Path(self.docker_mnt) / kwargs.get("ctf_kernel", "")
            self.rootfs = Path(self.docker_mnt) / kwargs.get("ctf_fs", "")
        else:
            self.kernel = Path(self.docker_mnt) / self.kernel_root / "arch" / self.arch / "boot" / "Image"
            self.rootfs = Path(self.docker_mnt) / self.rootfs_dir / (self.rootfs_base + self.arch + self.rootfs_ftype)
        self.qemu_arch = adjust_qemu_arch(self.arch)
        self.cmd = None

    def run(self):
        super().run(check_existing=True)

    def infer_qemu_fs_mount(self) -> str:
        r = self.rootfs if self.ctf else Path(*self.rootfs.parts[2:])
        magic = sp.run(f"file {r}", shell=True, capture_output=True)
        rootfs = self.rootfs.name if self.ctf else self.rootfs
        if b"cpio archive" in magic.stdout:
            return f" -initrd {rootfs}"
        elif b"filesystem data" in magic.stdout:
            return f" -drive file={rootfs},format=raw"
        elif b"qemu qcow" in magic.stdout.lower():
            return f" -drive file={rootfs}"
        else:
            logger.error(f"Unsupported rootfs type: {magic.stdout}")
            exit(-1)

    def infer_panic_behavior(self) -> int:
        if self.panic == "reboot":
            return -1
        elif self.panic == "halt":
            return 0
        elif "wait" in self.panic:
            try:
                ret = int(self.panic.split(" ")[1])
                return ret
            except (IndexError, ValueError):
                return 15
        else:
            logger.error("Unknown requested panic behavior...")
            exit(-1)

    def _add_smep_smap(self) -> None:
        if self.smep:
            self.cmd += ",+smep"
        if self.smap:
            self.cmd += ",+smap"

    def _ensure_container_is_up(self):
        import time

        # FIXME: Ugly hack to make us allow getting the container object.
        time.sleep(1)
        self.container = self.client.containers.get(f"{self.tag}")
        self.wait_for_container()

    def run_container(self):
        mount_point = self.ctf_mount if self.ctf else Path.cwd()
        kernel = Path(self.docker_mnt) / self.kernel.name if self.ctf else self.kernel
        dcmd = f'docker run --name {self.tag} -it --rm -v {mount_point}:/io --net="host" like_debuggee '
        self.cmd = f"qemu-system-{self.qemu_arch} -m {self.memory} -smp {self.smp} -kernel {kernel}"
        if self.qemu_arch == "aarch64":
            self.cmd += " -cpu cortex-a72"
            self.cmd += ' -machine type=virt -append "console=ttyAMA0 root=/dev/vda'
        elif self.qemu_arch == "x86_64":
            self.cmd += " -cpu qemu64"
            self._add_smep_smap()
            self.cmd += ' -append "console=ttyS0 root=/dev/sda'
        else:
            logger.error(f"Unsupported architecture: {self.qemu_arch}")
            exit(-1)
        self.cmd += " earlyprintk=serial net.ifnames=0"
        if not self.kaslr:
            self.cmd += " nokaslr"
        else:
            self.cmd += " kaslr"
        if not self.smep:
            self.cmd += " nosmep"
        if not self.smap:
            self.cmd += " nosmap"
        if not self.kpti:
            self.cmd += " nopti"
        else:
            self.cmd += " pti=on"
        self.cmd += f' oops=panic panic={self.infer_panic_behavior()}"'
        self.cmd += self.infer_qemu_fs_mount()
        self.cmd += " -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.kvm and self.qemu_arch == "x86_64":
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        tmux("selectp -t 1")
        runner = f"{dcmd} {self.cmd}"
        tmux_shell(runner)
        self._ensure_container_is_up()
