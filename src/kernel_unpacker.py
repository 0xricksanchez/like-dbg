#!/usr/bin/env python3

import shutil
import subprocess as sp
import tarfile
from pathlib import Path

from loguru import logger
from tqdm import tqdm

from .misc import cfg_setter, is_reuse, new_context


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL UNPACKER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelUnpacker:
    def __init__(self, p: Path, **kwargs) -> None:
        cfg_setter(self, ["kernel_general"])
        self.kernel_root = Path(self.kernel_root)
        self.archive = p
        self.ex_name = Path(".".join(self.archive.name.split(".")[:-2]))  # FIXME only works for formats like .tar.gz
        self.dst_content = None
        self.history = Path(".hist")
        self.skip_prompts = kwargs.get("skip_prompts", False)

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
            sp.run("make clean", shell=True)

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
                if self.skip_prompts:
                    logger.info("Re-using existing vmlinux")
                    return 1
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
