#!/usr/bin/env python3

import configparser
import os
import re
import shutil
import subprocess as sp
import tarfile
import termios
import urllib.request
from contextlib import contextmanager
from termios import tcflush, TCIFLUSH
from pathlib import Path
from sys import exit, stdin
from typing import List

import docker
import requests
import tqdm
from fabric import Connection
from loguru import logger
from tqdm import tqdm

config = Path.cwd() / 'config.ini'


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | MISC QOL functions                                                                                  |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
def cfg_setter(obj, sections: List[str]) -> None:
    cfg = configparser.ConfigParser()
    cfg.read(config)
    for sect in sections:
        for key in cfg[sect]:
            tmp = cfg[sect][key]
            val = tmp if tmp not in ['yes', 'no'] else cfg[sect].getboolean(key)
            setattr(obj, key, val)


def is_reuse(p: str) -> bool:
    choice = "y"
    logger.info(f"Found {p}. Re-use it? [Y/n]")
    tcflush(stdin, TCIFLUSH)
    tmp = input().lower()
    if tmp != "":
        choice = tmp
    if choice in ["y", "yes"]:
        logger.debug(f"Reusing existing {p}...")
        return True
    else:
        return False


def adjust_arch(arch):
    if arch == 'arm64':
        return 'aarch64'
    else:
        return arch


def tmux(cmd: str) -> None:
    sp.run(f"tmux {cmd} > /dev/null", shell=True)


def tmux_shell(cmd: str) -> None:
    tmux(f"send-keys '{cmd}' 'C-m'")


@contextmanager
def new_context(location: Path):
    cur_cwd = Path.cwd()
    try:
        os.chdir(location)
        yield
    finally:
        os.chdir(cur_cwd)


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
    def __init__(self) -> None:
        cfg_setter(self, ['kernel_dl'])
        self.commit = self._set_commit()
        self.choice = self._set_choice()
        logger.info(f"Using kernel with (tag/commit) {self.choice}")
        self.dl_uri = self._set_dl_uri()
        self.archive = Path(f"linux-{self.choice}.tar.gz")
        logger.debug(f"Kernel snap: {self.dl_uri}")

    def _set_commit(self):
        if any([self.tag, self.mmp]):
            return self.commit
        elif self.commit:
            return self.commit
        else:
            self._resolve_latest()

    def _resolve_latest(self) -> str:
        commit_re = rb"commit\/\?id=[0-9a-z]*"
        r = requests.get(self.commit_uri)
        search_res = re.search(commit_re, r.content)
        if search_res.group():
            commit = search_res.group().split(b"=")[1].decode()
            logger.debug(f"Found latest commit: {commit}")
            return commit
        else:
            logger.error("Resolving latest commit")
            exit(-1)

    def _set_choice(self):
        if self.mmp:
            return self.mmp
        elif self.tag:
            return self.tag
        else:
            return self.commit

    def _set_dl_uri(self):
        if self.mmp:
            (major, minor, patch) = tuple(self.mmp.split('.'))
            self.mmp_uri = self.mmp_uri.replace('KMAJOR', major)
            self.mmp_uri = self.mmp_uri.replace('KMINOR', minor)
            self.mmp_uri = self.mmp_uri.replace('KPATCH', patch)
            return self.mmp_uri
        else:
            return "{self.snap_uri}{self.choice}.tar.gz"

    def is_present(self) -> bool:
        if Path(self.archive).exists():
            logger.info("Kernel archive already exists locally. Skipping download...")
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
    def __init__(self, p: Path) -> None:
        cfg_setter(self, ['kernel_general'])
        self.kernel_root = Path(self.kernel_root)
        self.archive = p
        self.ex_name = Path('.'.join(self.archive.name.split('.')[:-2]))  # FIXME only works for formats like .tar.gz
        self.dst_content = None
        self.history = Path('.hist')

    def _is_new(self):
        if self.history.exists():
            entry = self.history.read_text()
            if entry == self.archive:
                return 0
        else:
            self.history.write_text(self.archive)
        return 1

    def _make_clean(self):
        logger.debug("Same kernel version already unpacked. Running 'make clean' just in case...")
        with new_context(self.kernel_root):
            sp.run('make clean', shell=True)

    def _is_dest_empty(self) -> bool:
        if self.kernel_root.exists():
            self.content = [x.name for x in self.kernel_root.iterdir()]
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
        if not is_reuse("vmlinux"):
            self._purge(self.kernel_root)
            self._unpack_targz()
            return 0
        return 1

    def _unpack_targz(self) -> None:
        if not tarfile.is_tarfile(self.archive):
            logger.error("Invalid archive format. Exiting...")
            exit(-1)

        logger.info("Unpacking kernel archive...")
        with tarfile.open(self.archive, mode="r") as t:
            members = t.getmembers()
            for member in tqdm(iterable=members, total=len(members)):
                t.extract(member)
        self.ex_name.rename(self.kernel_root)

    @staticmethod
    def _purge(p: Path) -> None:
        logger.info("Purging unclean kernel build environment...")
        shutil.rmtree(p, ignore_errors=True)

    def run(self) -> int:
        if not self._is_dest_empty():
            if self._is_vmlinux():
                if self._reuse_existing_vmlinux():
                    return 1
            else:
                self._make_clean()
                return 0
        if self._is_new():
            self._purge(self.kernel_root)
            self._unpack_targz()
        else:
            self._make_clean()
        return 0


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DOCKER RUNNER                                                                                       |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class DockerRunner:
    def __init__(self) -> None:
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
        # TODO remove hardcoded values in favor of a config
        self.ssh_conn = Connection(f"{self.user}@localhost:{self.ssh_fwd_port}",
                                   connect_kwargs={"key_filename": ".ssh/like.id_rsa"}
                                   )

    def build_image_hl(self):
        image = self.client.images.build(
            path=str(self.dockerfile_ctx),
            dockerfile=self.dockerfile_path,
            tag=self.tag
        )[0]
        return image

    def build_image(self):
        logger.debug(self.__dict__)
        for log_entry in self.cli.build(
                path=str(self.dockerfile_ctx),
                dockerfile=self.dockerfile,
                tag=self.tag,
                decode=True,
                buildargs=self.buildargs
        ):
            v = next(iter(log_entry.values()))
            if isinstance(v, str):
                v = ' '.join(v.strip().split())
                if v:
                    logger.debug(v)

    def get_image(self):
        try:
            image = self.client.images.get(self.tag)
            return image
        except docker.errors.ImageNotFound:
            return None

    def run(self):
        if not self.image:
            logger.info(f"Building fresh image for {type(self).__name__}")
            self.build_image()
            self.image = self.get_image()
        self.run_container()

    def run_container(self):
        pass

    def stop_container(self):
        self.container.stop()

    def check_existing(self) -> None:
        self.image = self.get_image()
        if self.image and not is_reuse(self.image.tags[0]):
            self.image = None


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL BUILDER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelBuilder(DockerRunner):
    def __init__(self) -> None:
        super().__init__()
        cfg_setter(self, ['kernel_general', 'kernel_builder', 'general', 'kernel_builder_docker'])
        self.cc = f'CC={self.compiler}' if self.compiler else ''
        self.llvm_flag = '' if 'gcc' in self.cc else 'LLVM=1'
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.guarantee_ssh(self.ssh_dir)
        self.tag = self.tag + f"_{self.arch}"
        self.buildargs = {
            'USER': self.user,
            'CC': self.compiler,
            'LLVM': '0' if self.compiler == 'gcc' else '1',
            'TOOLCHAIN_ARCH': adjust_arch(self.arch),
            'ARCH': self.arch,
        }

    def _run_ssh(self, cmd: str) -> int:
        return self.ssh_conn.run(f"cd {self.docker_mnt}/{self.kernel_root} && {cmd}").exited

    def _apply_patches(self):
        if Path(self.patch_dir).exists():
            patch_files = [x for x in Path(self.patch_dir).iterdir()]
            logger.debug(f"Applying patches...: {patch_files}")
            for pfile in patch_files:
                if self._run_ssh(f'patch -p1 < ../{self.patch_dir}/{pfile.name}') != 0:
                    logger.error(f"Patching: {pfile}")
                    exit(-1)

    def _build_mrproper(self):
        self._run_ssh(f"{self.cc} ARCH={self.arch} make mrproper")

    def _build_arch(self):
        # TODO check how we need to sanitize the [general] config arch field to reflect the make options
        # All i know is it works if arch is x86_64
        if self.arch == 'x86_64':
            self._run_ssh(f"{self.cc} {self.llvm_flag} make {self.arch}_defconfig")
        else:
            self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make defconfig")

    def _build_kvm_guest(self):
        self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make kvm_guest.config")

    def _configure_kernel(self):
        if self.mode == 'syzkaller':
            self._configure_syzkaller()
        elif self.mode == 'generic':
            self._configure_generic()
        else:
            self._configure_custom()

    def _configure_generic(self):
        self._run_ssh(f"./scripts/config {self.generic_args}")

    def _configure_syzkaller(self):
        self._run_ssh(f"./scripts/config {self.syzkaller_args}")

    def _configure_custom(self):
        params = '-e ' + ' -e '.join(self.enable_args.split())
        params += ' -d ' + ' -d '.join(self.disable_args.split())
        self._run_ssh(f'./scripts/config {params}')

    def _make(self):
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) all")
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) modules")

    def run_container(self):
        self.container = self.client.containers.run(
            self.image,
            volumes=[f"{Path.cwd()}:{self.docker_mnt}"],
            ports={"22/tcp": self.ssh_fwd_port},
            detach=True,
            tty=True,
        )
        self.init_ssh()
        if self.ssh_conn:
            self._build_mrproper()
            self._apply_patches()
            self._build_arch()
            self._build_kvm_guest()
            self._configure_kernel()
            self._make()
        else:
            logger.error("No ssh connection to docker")
            exit(-1)

    def run(self):
        logger.info("Building kernel. This may take a while...")
        self.image = self.get_image()
        super().run()
        logger.info("Successfully build the kernel")
        if self.arch == 'x86_64':
            kernel = Path(f'{self.kernel_root}/arch/x86/boot/bzImage')
            if kernel.exists():
                Path(Path.cwd() / kernel.parent.parent.parent / f"{self.arch}/boot/Image").symlink_to(Path.cwd() / kernel)
        self.stop_container()


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class RootFSBuilder(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ['rootfs_general', 'rootfs_builder', 'general'])
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.ssh_conn = self.init_ssh()
        self.guarantee_ssh(self.ssh_dir)
        self.rootfs_path = self.rootfs_dir + self.rootfs_base + self.arch + self.rootfs_ftype
        self.buildargs = {'USER': self.user}

    def run_container(self):
        qemu_arch = adjust_arch(self.arch)
        command = f"/home/{self.user}/rootfs.sh -n /{self.rootfs_path} -a {qemu_arch}"
        container = self.client.containers.run(
            self.image,
            volumes=[f"{Path.cwd() / 'io'}:{self.docker_mnt}"],
            detach=True,
            privileged=True,
            ports={"22/tcp": self.ssh_fwd_port},
            command=command
        )
        gen = container.logs(stream=True, follow=True)
        [logger.debug(log.strip().decode()) for log in gen]

    def check_existing(self) -> bool:
        logger.debug(f'Checking for existing rootfs: {self.rootfs_path}')
        if Path(self.rootfs_path).exists():
            return is_reuse(self.rootfs_path)
        else:
            return False

    def run(self) -> None:
        if not self.check_existing():
            self.image = self.get_image()
            logger.debug(f"found rootfs_builder: {self.image}")
            super().run()


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ['general', 'debugger', 'kernel_general'])
        self.buildargs = {'USER': self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def run_container(self) -> None:
        entrypoint = f"/home/{self.user}/debugger.sh -a {self.arch} -p {self.docker_mnt}"
        runner = f'docker run -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {Path.cwd() / self.kernel_root}:/io --net="host" {self.tag} {entrypoint}'
        tmux("selectp -t 2")
        tmux_shell(runner)

    def run(self):
        self.check_existing()
        super().run()


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGEE                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debuggee(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ['debuggee', 'debuggee_docker', 'general', 'kernel_general', 'rootfs_general'])
        self.img = Path(self.docker_mnt) / self.rootfs_dir / (self.rootfs_base + self.arch + self.rootfs_ftype)
        self.qemu_arch = adjust_arch(self.arch)
        self.cmd = None
        self.buildargs = {'USER': self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def run(self):
        self.check_existing()
        logger.error(self.image)
        super().run()

    def run_container(self):
        dcmd = 'docker run -it --rm -v /home/raven/Git/like-dbg/:/io --net="host" like_debuggee '
        self.cmd = f"qemu-system-{self.qemu_arch} -m {self.memory} -smp {self.smp} -kernel {self.docker_mnt}/{self.kernel_root}/arch/{self.arch}/boot/Image "
        if self.qemu_arch == 'aarch64':
            self.cmd += "-cpu cortex-a72 -machine type=virt -append \"console=ttyAMA0 root=/dev/vda "
        elif self.qemu_arch == 'x86_64':
            self.cmd += " -append \"console=ttyS0 root=/dev/sda "
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
        self.cmd += f" panic=1\" -drive file={self.img},format=raw -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 -net nic,model=e1000 -nographic -pidfile vm.pid"
        if self.kvm and self.qemu_arch == 'x86_64':
            self.cmd += " -enable-kvm"
        if self.gdb:
            self.cmd += " -S -s"
        #logger.debug(self.cmd)
        tmux("selectp -t 1")
        tmux_shell(f'{dcmd} {self.cmd}')

def main():
    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")

    karchive = KernelDownloader().run()
    if not KernelUnpacker(karchive).run():
        KernelBuilder().run()
    RootFSBuilder().run()


    Debuggee().run()
    tmux("selectp -t 0")
    Debugger().run()
    tmux("selectp -t 0")

    logger.debug("Loaded tmux config")
    tmux_shell("tmux source-file .tmux.conf")


if __name__ == "__main__":
    main()
