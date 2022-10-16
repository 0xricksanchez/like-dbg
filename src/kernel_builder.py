#!/usr/bin/env python3

import re
import time
from os import getuid
from pathlib import Path
import subprocess as sp
from invoke.exceptions import UnexpectedExit

from loguru import logger

from .docker_runner import DockerRunner
from .misc import adjust_arch, adjust_toolchain_arch, cfg_setter, cross_compile

MISC_DRVS_PATH = Path("drivers/misc/")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL BUILDER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelBuilder(DockerRunner):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["kernel_builder", "kernel_builder_docker"], user_cfg, exclude_keys=["kernel_root"], cherry_pick={"debuggee": ["kvm"]})
        self.cc = f"CC={self.compiler}" if self.compiler else ""
        self.llvm_flag = "" if "gcc" in self.cc else "LLVM=1"
        self.guarantee_ssh(self.ssh_dir)
        self.tag = self.tag + f"_{self.arch}"
        self.dirty = kwargs.get("assume_dirty", False)
        tmp_arch = adjust_arch(self.arch)
        self.config = Path(self.config)
        self.buildargs = self.buildargs | {
            "CC": self.compiler,
            "LLVM": "0" if self.compiler == "gcc" else "1",
            "TOOLCHAIN_ARCH": adjust_toolchain_arch(self.arch),
            "CROSS_COMPILE": cross_compile(self.arch),
            "ARCH": tmp_arch,
        }
        self.arch = tmp_arch

    @staticmethod
    def make_sudo(cmd: str) -> str:
        if getuid() == 0:
            return f"sudo {cmd}"
        else:
            return cmd

    def _run_ssh(self, cmd: str, **kwargs) -> int:
        cmd = self.make_sudo(cmd)
        warn = kwargs.get("warn", False)
        return self.ssh_conn.run(f"cd {self.docker_mnt}/{self.kernel_root} && {cmd}", echo=True, warn=warn).exited

    def _apply_patches(self):
        if self.patch_dir and Path(self.patch_dir).exists():
            patch_files = [x for x in Path(self.patch_dir).iterdir()]
            if patch_files:
                for pfile in patch_files:
                    logger.debug(f"Patching: {pfile}")
                    if self._run_ssh(f"patch -p1 < ../../{self.patch_dir}/{pfile.name} > /dev/null", warn=True) != 0:
                        logger.error(f"Failed to apply patch: {pfile}... Continuing anyway!")

    def _build_mrproper(self):
        self._run_ssh(f"{self.cc} ARCH={self.arch} make mrproper")

    def _build_arch(self) -> None:
        # TODO check how we need to sanitize the [general] config arch field to reflect the make options
        # All i know is it works if arch is x86_64
        if self.arch == "x86_64":
            self._run_ssh(f"{self.cc} {self.llvm_flag} make {self.arch}_defconfig")
        else:
            self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make defconfig")

    def _build_kvm_guest(self):
        self._run_ssh(f"{self.cc} {self.llvm_flag} ARCH={self.arch} make kvm_guest.config")

    def _configure_kernel(self) -> None:
        if self.mode == "syzkaller":
            params = self.syzkaller_args
        elif self.mode == "generic":
            params = self.generic_args
        elif self.mode == "custom":
            params = self._configure_custom()
        if self.extra_args:
            params = self._configure_extra_args(params)
        if params:
            self._run_ssh(f"./scripts/config {params}")

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

    def _configure_custom(self) -> str:
        params = "-e " + " -e ".join(self.enable_args.split())
        params += " -d " + " -d ".join(self.disable_args.split())
        return params

    def _make_clean(self) -> None:
        logger.debug("Running 'make clean' just in case...")
        self._run_ssh("make clean")

    def _make(self):
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) all")
        self._run_ssh(f"{self.cc} ARCH={self.arch} {self.llvm_flag} make -j$(nproc) modules")

    def _wait_for_container(self) -> None:
        logger.info("Waiting for Container to be up...")
        while True:
            c = self.cli.inspect_container(self.container.id)
            if c["State"]["Health"]["Status"] != "healthy":
                time.sleep(1)
            else:
                break

    def _add_modules(self) -> None:
        for d in Path(self.custom_modules).iterdir():
            if not d.is_dir():
                continue
            dst = f"{Path(self.kernel_root) / MISC_DRVS_PATH}"
            sp.run(f"cp -fr {d} {dst}", shell=True)
            kcfg_mod_path = Path(dst) / d.name / "Kconfig"
            mod_kcfg_content = kcfg_mod_path.read_text()
            tmp = "_".join(re.search(r"config .*", mod_kcfg_content)[0].upper().split())
            ins = f"obj-$({tmp}) += {d.name}/\n"
            if ins.strip() not in Path(f"{dst}/Makefile").read_text():
                with open(f"{dst}/Makefile", "a") as g:
                    g.write(ins)
            with open(f"{dst}/Kconfig", "r") as f:
                contents = f.readlines()
            ins = f"""source "{MISC_DRVS_PATH / d.name / 'Kconfig'}"\n"""
            if ins not in contents:
                contents.insert(len(contents) - 1, ins)
                with open(f"{dst}/Kconfig", "w") as kc:
                    kc.writelines(contents)
            logger.debug(f"Added module {d} to the kernel")

    def run_container(self) -> None:
        logger.info("Building kernel. This may take a while...")
        try:
            if self.custom_modules:
                self._add_modules()
            volumes = {f"{Path.cwd()}": {"bind": f"{self.docker_mnt}", "mode": "rw"}}
            if self.mode == "config":
                volumes |= {f"{self.config.absolute().parent}": {"bind": "/tmp/", "mode": "rw"}}
            self.container = self.client.containers.run(
                self.image,
                volumes=volumes,
                ports={"22/tcp": self.ssh_fwd_port},
                detach=True,
                tty=True,
            )
            self._wait_for_container()
            self.init_ssh()
            if self.dirty:
                self._make_clean()
            if self.mode != "config":
                self._build_mrproper()
                self._apply_patches()
                self._build_arch()
                if self.kvm:
                    self._build_kvm_guest()
            else:
                self._run_ssh(f"cp /tmp/{self.config.stem} .config")
            self._configure_kernel()
            self._make()
        except FileNotFoundError as e:
            logger.error(f"Failed to find file: {e}")
            exit(-1)
        except UnexpectedExit as e:
            logger.error(f"A command caused an unexpected exit: {e}")
            exit(-1)
        else:
            logger.info("Successfully build the kernel")
            if self.arch == "x86_64":
                cmd = self.make_sudo("ln -s bzImage Image")
                self.ssh_conn.run(f"cd {self.docker_mnt}/{self.kernel_root}/arch/{self.arch}/boot && {cmd}", echo=True)
        finally:
            self.stop_container()

    def run(self) -> None:
        super().run(check_existing=True)
