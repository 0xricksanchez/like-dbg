#!/usr/bin/env python3

import pathlib
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

    def _configure_kernel(self):
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

    def _make(self):
        self._run_generic("make -j$(nproc) all")
        self._run_generic("make -j$(nproc) modules")

    def run(self):
        logger.info("Building kernel. This may take a while...")
        with self.build_context(LINUX_ROOT_DIR):
            self._build_mrproper()
            self._build_arch()
            self._build_kvm_guest()
            self._configure_kernel()
            self._make()
        logger.info("Successfully build the kernel")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | ROOTFS BUILDER                                                                                      |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+

import docker

# TODO remove hardcoded values into a config file that is being parsed
ROOTFS = Path("./io/fs.qcow2")

# TODO Make all them others inherit from this thing
class DockerRunner:
    pass

class RootfsBuilder:
    def __init__(self):
        self.dockerfile_base = Path.cwd()
        self.client = docker.from_env()
        self.image = None

    def _build_runner(self) -> None:
        logger.debug(self.dockerfile_base)
        ret = self.client.images.build(
            path=self.dockerfile_base.name, dockerfile=self.dockerfile_base / ".dockerfile_base_arch", tag="rootfs"
        )
        self.image = ret[0]
        logger.debug(f"Image: {self.image}")
        container = self.client.containers.run(
            self.image, privileged=True, volumes=[f"{Path.cwd() / 'io'}:/io"], command="/io/scripts/rootfs.sh", detach=True
        )
        gen = container.logs(stream=True, follow=True)
        [logger.debug(log.strip()) for log in gen]

    def run(self) -> None:
        # TODO check whether kernel arch matches rootfs arch
        if ROOTFS.exists():
            choice = "y"
            logger.info("Found a rootfs locally. Re-use it? [Y/n]")
            tmp = input().lower()
            if tmp != "":
                choice = tmp
            if choice in ["y", "yes"]:
                logger.info("Reusing existing rootfs...")
        else:
            logger.info("Building fresh rootfs")
            self._build_runner()


class Debugee:
    def __init__(self):
        pass

    def run(self):
        pass


def main():
    # karchive = KernelDownloader(None, '5.15').run()
    # karchive = KernelDownloader('47700948a4abb4a5ae13ef943ff682a7f327547a', None).run()
    # KernelUnpacker(karchive).run()
    # KernelBuilder().run()
    RootfsBuilder().run()


if __name__ == "__main__":
    main()
