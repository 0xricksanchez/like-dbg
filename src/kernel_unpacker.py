#!/usr/bin/env python3

import shutil
import tarfile
from pathlib import Path

from loguru import logger
from tqdm import tqdm

from .misc import cfg_setter, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL UNPACKER                                                                                     |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelUnpacker:
    def __init__(self, p: Path, **kwargs) -> None:
        cfg_setter(self, ["general"])
        self.archive = p
        self.ex_name = ".".join(self.archive.name.split(".")[:-2])  # FIXME only works for formats like .tar.gz
        if not Path(self.kernel_root).exists():
            Path(self.kernel_root).mkdir()
        self.kernel_root = Path(self.kernel_root) / (self.ex_name + f"_{self.arch}")
        self.dst_content = None
        self.skip_prompts = kwargs.get("skip_prompts", False)

    def _is_dest_empty(self) -> bool:
        self.content = [x.name for x in self.kernel_root.iterdir()]
        if self.content:
            return False
        else:
            return True

    def _is_vmlinux(self) -> int:
        if "vmlinux" in self.content:
            return 1
        return 0

    def _reuse_existing_vmlinux(self) -> int:
        if is_reuse(f"{self.kernel_root}/vmlinux"):
            return 1
        return 0

    def _unpack_targz(self) -> None:
        if not tarfile.is_tarfile(self.archive):
            logger.critical("Invalid archive format. Exiting...")
            exit(-1)

        logger.info("Unpacking kernel archive...")
        with tarfile.open(self.archive, mode="r") as t:
            members = t.getmembers()
            for member in tqdm(iterable=members, total=len(members)):
                t.extract(member)
        Path(self.ex_name).rename(self.kernel_root)

    @staticmethod
    def _purge(p: Path) -> None:
        logger.debug("Purging unclean kernel build environment...")
        shutil.rmtree(p, ignore_errors=True)

    def run(self) -> dict:
        res = {"kroot": self.kernel_root}
        if not self.kernel_root.exists():
            logger.debug(f"{self.kernel_root} does not exist. Unpacking fresh kernel...")
            self._unpack_targz()
            return res | {"status_code": 0}
        elif not self._is_dest_empty():
            if self._is_vmlinux():
                if self.skip_prompts or self._reuse_existing_vmlinux():
                    logger.info(f"Re-using existing {self.kernel_root}/vmlinux")
                    return res | {"status_code": 1}
                else:
                    return res | {"status_code": 0, "assume_dirty": True}
            else:
                logger.debug(f"{self.kernel_root} does exist, but contains no kernel. Assuming dirty directory...")
                return res | {"status_code": 0, "assume_dirty": True}
        else:
            logger.debug(f"{self.kernel_root} does exist, but is empty. Purging it and unpacking fresh kernel...")
            self._purge(self.kernel_root)
            self._unpack_targz()
            return res | {"status_code": 0}
