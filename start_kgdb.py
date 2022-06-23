#!/usr/bin/env python3

import requests
import shutil
import tarfile
from typing import Optional
import re
import tqdm
from loguru import logger
from tqdm import tqdm
import os
from contextlib import contextmanager
import urllib.request
from pathlib import Path
import subprocess as sp

LINUX_COMMIT_URI = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/"
LINUX_SNAP_BASE_URI = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-"
LINUX_ROOT_DIR = Path("./kernel_root")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | TQDM WGET WITH PROGRESS BAR                                                                         |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class DLProgressBarTQDM(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None) -> None:
        if tsize is not None:
            self.total = tsize
        return self.update(b * bsize - self.n)  # also sets self.n = b * bsize


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL DOWNLOADER                                                                                   |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelDownloader:
    def __init__(self, commit: Optional[str], tag: Optional[str]) -> None:
        self.tag = tag
        self.commit = commit if commit else self.resolve_latest()
        self.choice = self.tag if self.tag else self.commit
        logger.debug(f"Will continue with Kernel {self.choice}")
        self.dl_uri = f"{LINUX_SNAP_BASE_URI}{self.choice}.tar.gz"
        self.archive = Path(f"linux-{self.choice}.tar.gz")
        logger.debug(f"Kernel snap: {self.dl_uri}")

    @staticmethod
    def resolve_latest() -> str:
        commit_re = rb"commit\/\?id=[0-9a-z]*"
        r = requests.get(LINUX_COMMIT_URI)
        search_res = re.search(commit_re, r.content)
        if search_res.group():
            commit = search_res.group().split(b"=")[1].decode()
            logger.debug(f"Found latest commit: {commit}")
            return commit
        else:
            logger.error("Resolving latest commit")
            exit(-1)

    def is_present(self) -> bool:
        if Path(self.archive).exists():
            logger.info("Kernel archive already exists locally. Skipping download")
            return True
        else:
            return False

    def download_kernel_archive(self) -> None:
        logger.info(f"Downloading {self.dl_uri}... This may take a while!")
        with DLProgressBarTQDM(unit="B", unit_scale=True, miniters=1, desc=self.archive.name) as t:
            urllib.request.urlretrieve(self.dl_uri, filename=self.archive, reporthook=t.update_to)
            t.total = t.n

    def run(self):
        if not self.is_present():
            self.download_kernel_archive()
        return self.archive


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL UNPACKER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelUnpacker:
    def __init__(self, inp: Path) -> None:
        self.archive = inp
        self.ex_name = Path(self.archive.name.split(".")[0])
        self.dst_content = None

    def _is_dest_empty(self) -> bool:
        if LINUX_ROOT_DIR.exists():
            self.content = [x for x in LINUX_ROOT_DIR.iterdir()]
            if self.content:
                return False
            else:
                return True
        else:
            return True

    def _is_vmlinux(self) -> int:
        if "vmlinux" in self.content:
            return 1
        else:
            return 0

    def _reuse_existing_vmlinux(self) -> int:
        choice = "y"
        logger.info('Found "vmlinux" locally. Re-use it? [Y/n]')
        tmp = input().lower()
        if tmp != "":
            choice = tmp
        if choice in ["y", "yes"]:
            logger.info("Reusing existing kernel...")
            return 1
        else:
            self._purge()
            self._unpack_targz()
            return 0

    def _unpack_targz(self) -> None:
        if not tarfile.is_tarfile(self.archive):
            logger.error("Did not get a valid kernel tar archive for unpacking. Exiting...")
            exit(-1)

        logger.info("Unpacking kernel archive...")
        with tarfile.open(self.archive, mode="r") as t:
            members = t.getmembers()
            for member in tqdm(iterable=members, total=len(members)):
                t.extract(member)
        self.ex_name.rename(LINUX_ROOT_DIR)

    @staticmethod
    def _purge() -> None:
        logger.info("Purging unclean kernel build environment...")
        shutil.rmtree(LINUX_ROOT_DIR)

    def run(self) -> int:
        if not self._is_dest_empty():
            if self._is_vmlinux():
                if self._reuse_existing_vmlinux():
                    return 0
        self._purge()
        self._unpack_targz()
        return 0


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL BUILDER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelBuilder:
    @staticmethod
    @contextmanager
    def build_context(location: Path):
        cur_cwd = Path.cwd()
        try:
            os.chdir(location)
            yield
        finally:
            os.chdir(cur_cwd)

    def apply_patches(self):
        # TODO add option to apply patch files
        pass

    @staticmethod
    def _run_generic(cmd: str) -> int:
        ret = sp.run(cmd, shell=True)
        if ret.returncode != 0:
            logger.error(f"{cmd} in {Path.cwd()}")
            exit(ret.returncode)
        return ret.returncode

    def _build_mrproper(self):
        self._run_generic("make mrproper")

    def _build_arch(self):
        # TODO add non amd64 builds
        self._run_generic("make x86_64_defconfig")

    def _build_kvm_guest(self):
        self._run_generic("make kvm_guest.config")

    def _configure_kernel(self, kernel_config: str):
        match kernel_config:
            case "syzkaller":
                self._configure_syzkaller()
            case _:
                self._configure_generic()

    def _configure_generic(self):
        self._run_generic(
            "./scripts/config \
            -e DEBUG_KERNEL \
            -e DEBUG_INFO \
            -e DEBUG_INFO_DWARF4 \
            -e FRAME_POINTER \
            -e GDB_SCRIPTS \
            -e KALLSYMS \
            -d DEBUG_INFO_DWARF5 \
            -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
            -d DEBUG_INFO_REDUCED \
            -d DEBUG_INFO_COMPRESSED \
            -d DEBUG_INFO_SPLIT \
            -d RANDOMIZE_BASE"
        )

    def _configure_syzkaller(self):
        self._run_generic(
            "./scripts/config \
            -e DEBUG_FS -e DEBUG_INFO \
            -e KALLSYMS -e KALLSYMS_ALL \
            -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS -e NET_NS -e USER_NS \
            -e CGROUP_PIDS -e MEMCG -e CONFIGFS_FS -e SECURITYFS \
            -e KASAN -e KASAN_INLINE -e WARNING \
            -e FAULT_INJECTION -e FAULT_INJECTION_DEBUG_FS \
            -e FAILSLAB -e FAIL_PAGE_ALLOC \
            -e FAIL_MAKE_REQUEST -e FAIL_IO_TIMEOUT -e FAIL_FUTEX \
            -e LOCKDEP -e PROVE_LOCKING \
            -e DEBUG_ATOMIC_SLEEP \
            -e PROVE_RCU -e DEBUG_VM \
            -e REFCOUNT_FULL -e FORTIFY_SOURCE \
            -e HARDENED_USERCOPY -e LOCKUP_DETECTOR \
            -e SOFTLOCKUP_DETECTOR -e HARDLOCKUP_DETECTOR \
            -e BOOTPARAM_HARDLOCKUP_PANIC \
            -e DETECT_HUNG_TASK -e WQ_WATCHDOG \
            --set-val DEFAULT_HUNG_TASK_TIMEOUT 140 \
            --set-val RCU_CPU_STALL_TIMEOUT 100 \
            -e UBSAN \
            -d RANDOMIZE_BASE"
        )

    def _make(self):
        self._run_generic("make -j$(nproc) all")
        self._run_generic("make -j$(nproc) modules")

    def run(self):
        logger.info("Building kernel. This may take a while...")
        with self.build_context(LINUX_ROOT_DIR):
            self._build_mrproper()
            self._build_arch()
            self._build_kvm_guest()
            self._configure_kernel("generic")
            self._make()
        logger.info("Successfully build the kernel")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+

import docker
from fabric import Connection

# TODO remove hardcoded values into a config file that is being parsed
ROOTFS = Path("./io/rootfs.img")
SSHDIR = Path(".ssh")

# TODO Make all them others inherit from this thing
class DockerRunner:
    pass


class RootfsBuilder:
    def __init__(self):
        self.dockerfile_base = Path.cwd()
        self.client = docker.from_env()
        self.image = None
        self.guarantee_ssh()
        self.ssh_conn = None
        self.rootfs_name = ROOTFS.name

    @staticmethod
    def guarantee_ssh():
        if SSHDIR.exists() and os.listdir(SSHDIR):
            logger.debug("Assuming ssh keys are present...")
        else:
            logger.debug("Generating new ssh key pair...")
            SSHDIR.mkdir()
            sp.run(f'ssh-keygen -f {SSHDIR / "like.id_rsa"} -t rsa -N ""', shell=True)

    def _init_ssh(self):
        # TODO remove hardcoded values in favor of a config
        # TODO do we even want this
        self.ssh_conn = Connection("dbg@localhost:2222", connect_kwargs={"key_filename": ".ssh/like.id_rsa"})

    def _build_rootfs(self) -> None:
        logger.info("Building fresh rootfs")
        ret = self.client.images.build(path=str(self.dockerfile_base), dockerfile=self.dockerfile_base / ".dockerfile_rootfs", tag="rootfs")
        self.image = ret[0]
        logger.debug(f"Image: {self.image}")
        command = f"/home/dbg/rootfs.sh -n {self.rootfs_name}"
        container = self.client.containers.run(
            self.image, volumes=[f"{Path.cwd() / 'io'}:/io"], privileged=True, detach=True, ports={"22/tcp": 2222}, command=command
        )
        gen = container.logs(stream=True, follow=True)
        [logger.debug(log.strip()) for log in gen]

    def run(self) -> None:
        if ROOTFS.exists():
            choice = "y"
            logger.info("Found a rootfs locally. Re-use it? [Y/n]")
            tmp = input().lower()
            if tmp != "":
                choice = tmp
            if choice in ["y", "yes"]:
                logger.info("Reusing existing rootfs...")
            else:
                self._build_rootfs()
        else:
            self._build_rootfs()


"""
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel $KERNEL/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=$IMAGE/stretch.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
"""


class Debuggee:
    def __init__(self, kernel_root: Path, image: Path, arch: str, memory: int, smp: int, kvm: bool, dbg: bool, kaslr: bool):
        self.kernel_root = kernel_root
        self.img = image
        self.arch = arch
        self.mem = memory
        self.smp = smp
        self.kvm = kvm
        self.dbg = dbg
        self.kaslr = kaslr

    def run(self):
        cmd = f"qemu-system-{self.arch} -m {self.mem} -smp {self.smp} -kernel {self.kernel_root}/arch/{self.arch}/boot/bzImage"
        cmd += " -append \"console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" 
        if self.kaslr:
            cmd += "\""
        else:
            cmd += " nokaslr\""
        cmd += f" -drive file={self.img},format=raw -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.kvm:
            cmd += " -enable-kvm"
        if self.dbg:
            cmd += " -S -s"
        tmux_shell(cmd)


class Debugger:
    def __init__(self, arch: str, p: Path):
        self.mnt = Path("/io")
        self.arch = arch
        self.project_root = p
        self.dockerfile_base = Path.cwd()
        self.client = docker.from_env()
        self.image = None
        self.tag = "debugger"

    def _build_container(self):
        logger.info("Building debug container...")

        self.image = self.client.images.build(
            path=str(self.dockerfile_base), dockerfile=self.dockerfile_base / ".dockerfile_dbg", tag=self.tag
        )[0]
        self.tag = self.image.tags[0]
        logger.debug(f"Image: {self.image}")

    def _run_container(self):
        entrypoint = f"/home/dbg/debugger.sh -a {self.arch} -p {self.mnt}"
        runner = f'docker run -it --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {Path.cwd() / self.project_root}:/io --net="host" {self.tag} {entrypoint}'
        logger.debug(runner)

        # self.client.containers.run(
        #        self.image, volumes=[f"{Path.cwd()}:/io"],  detach=True, command=cmd, network_mode="host"
        # )

        tmux_shell(runner)

    def _runner(self):
        try:
            img = self.client.images.get(self.tag)
            self.tag = img.tags[0]
        except docker.errors.ImageNotFound:
            logger.debug("Did not find debugger")
            self._build_container()
        finally:
            self._run_container()

    def run(self):
        self._runner()


def tmux(cmd: str) -> None:
    sp.run(f"tmux {cmd}", shell=True)
    # os.system(f"tmux {cmd}")


def tmux_shell(cmd: str) -> None:
    tmux(f"send-keys '{cmd}' 'C-m'")


def main():
    # karchive = KernelDownloader(None, '5.15').run()
    # karchive = KernelDownloader('47700948a4abb4a5ae13ef943ff682a7f327547a', None).run()
    # KernelUnpacker(karchive).run()
    # KernelBuilder().run()
    # RootfsBuilder().run()

    # By now we should be in a tmux window
    # Run pwndbg container
    tmux_shell("tmux source-file .tmux.conf")
    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    tmux("splitw -h -p 50")
    tmux("selectp -t 1")
    tmux("splitw -v -p 50")

    # Then attach debugger
    tmux("selectp -t 0")
    Debugger("i386:x86-64:intel", Path("kernel_root")).run()

    # Start kernel first
    tmux("selectp -t 1")
    Debuggee(Path("kernel_root"), Path("io/rootfs.img"), "x86_64", 4096, 2, True, True, False).run()

if __name__ == "__main__":
    main()
