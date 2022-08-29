#!/usr/bin/env python3

import re
import time
from os import getuid
from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_arch, cfg_setter, canadian_cross


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL BUILDER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelBuilder(DockerRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        cfg_setter(self, ["kernel_builder", "general", "kernel_builder_docker"], exclude_keys=["kernel_root"])
        self.cc = f"CC={self.compiler}" if self.compiler else ""
        self.llvm_flag = "" if "gcc" in self.cc else "LLVM=1"
        self.cli = docker.APIClient(base_url=self.docker_sock)
        self.guarantee_ssh(self.ssh_dir)
        self.tag = self.tag + f"_{self.arch}"
        self.dirty = kwargs.get("assume_dirty", False)
        self.buildargs = {
            "USER": self.user,
            "CC": self.compiler,
            "LLVM": "0" if self.compiler == "gcc" else "1",
            "TOOLCHAIN_ARCH": adjust_arch(self.arch),
            "CANADIAN_CROSS": canadian_cross(self.arch),
            "ARCH": self.arch,
        }

    @staticmethod
    def make_sudo(is_sudo: bool) -> str:
        if is_sudo:
            return "sudo"
        else
        return ""

    def _run_ssh(self, cmd: str, is_sudo: bool) -> int:
        return self.ssh_conn.run(f"cd {self.docker_mnt}/{self.kernel_root} && {self.make_sudo(is_sudo)} {cmd}").exited

    def _apply_patches(self, is_sudo :bool):
        if self.patch_dir and Path(self.patch_dir).exists():
            patch_files = [x for x in Path(self.patch_dir).iterdir()]
            if patch_files:
                logger.debug(f"Applying patches...: {patch_files}")
                for pfile in patch_files:
                    if self._run_ssh(f"patch -p1 < ../../{self.patch_dir}/{pfile.name}", is_sudo) != 0:
                        logger.error(f"Patching: {pfile}")
                        exit(-1)

    def _build_mrproper(self, is_sudo: bool):
        self._run_ssh(f"{self.cc} ARCH={self.arch} make mrproper", is_sudo)

    def _build_arch(self, is_sudo: bool):
        # TODO check how we need to sanitize the [general] config arch field to reflect the make options
        # All i know is it works if arch is x86_64
        if self.arch == "x86_64":
            self._run_ssh(f"{self.make_sudo(is_sudo)} {{self.cc} {self.llvm_flag} make {self.arch}_defconfig", is_sudo)
        else:
            self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make defconfig", is_sudo)

    def _build_kvm_guest(self, is_sudo: bool):
        self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make kvm_guest.config", is_sudo)

    def _configure_kernel(self, is_sudo: bool):
        if self.mode == "syzkaller":
            params = self.syzkaller_args
        elif self.mode == "generic":
            params = self.generic_args
        else:
            params = self._configure_custom()
        if self.extra_args:
            params = self._configure_extra_args(params)
        self._run_ssh(f"./scripts/config {params}", is_sudo)

    def _configure_extra_args(self, params: str) -> str:
        for idx, opt in enumerate(self.extra_args.split()[1::2]):
            if opt in params:
                pattern = rf"[-][ed]{1}\s{opt}"
                params = re.sub(pattern, opt, params)
            else:
                new_opt = " ".join(self.extra_args.split()[idx * 2 : idx * 2 + 2])
                params += f" {new_opt}"
        logger.debug(params)
        return params

    def _configure_custom(self):
        params = "-e " + " -e ".join(self.enable_args.split())
        params += " -d " + " -d ".join(self.disable_args.split())
        return params

    def _make_clean(self, is_sudo: bool):
        logger.debug("Running 'make clean' just in case...")
        self._run_ssh(f"make clean", is_sudo)

    def _make(self, is_sudo: bool):
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) all", is_sudo)
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) modules", is_sudo)

    def _wait_for_container(self) -> None:
        logger.info("Waiting for Container to be up...")
        while True:
            c = self.cli.inspect_container(self.container.id)
            if c["State"]["Health"]["Status"] != "healthy":
                time.sleep(1)
            else:
                break

    def run_container(self):
        is_sudo = True if getuid() == 0 else False
        try:
            self.container = self.client.containers.run(
                self.image,
                volumes=[f"{Path.cwd()}:{self.docker_mnt}"],
                ports={"22/tcp": self.ssh_fwd_port},
                detach=True,
                tty=True,
            )
            self._wait_for_container()
            self.init_ssh()
            if self.dirty:
                self._make_clean(is_sudo)
            self._build_mrproper(is_sudo)
            self._apply_patches(is_sudo)
            self._build_arch(is_sudo)
            self._build_kvm_guest(is_sudo)
            self._configure_kernel(is_sudo)
            self._make(is_sudo)
        except Exception as e:
            logger.error(f"Oops: {e}")
            exit(-1)
        else:
            logger.info("Successfully build the kernel")
            if self.arch == "x86_64":
                self._run_ssh(f"cd arch/{self.arch}/boot/ && ln -s bzImage Image", is_sudo)
        finally:
            self.stop_container()

    def run(self):
        logger.info("Building kernel. This may take a while...")
        self.check_existing()
        super().run()
