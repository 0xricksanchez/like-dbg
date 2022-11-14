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
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["general"], user_cfg)
        self.archive = p
        self.ex_name = ".".join(self.archive.name.split(".")[:-2])
        if not Path(self.kernel_root).exists():
            Path(self.kernel_root).mkdir()
        self.kernel_root = Path(self.kernel_root) / (self.ex_name + f"_{self.arch}" + f"_{self.kernel_tag}")
        self.dst_content = None
        self.skip_prompts = kwargs.get("skip_prompts", False)

    def _is_dest_empty(self) -> bool:
        self.content = [x.name for x in self.kernel_root.iterdir()]
        if self.content:
            return False
        else:
            return True

    def _is_vmlinux(self) -> bool:
        if "vmlinux" in self.content:
            return True
        return False

    def _reuse_existing_vmlinux(self) -> bool:
        try:
            if is_reuse(f"{self.kernel_root}/vmlinux"):
                return True
            return False
        except Exception:
            return False

    def _unpack_targz(self) -> int:
        logger.info("Unpacking kernel archive...")
        try:
            with tarfile.open(self.archive, mode="r") as t:
                members = t.getmembers()
                for member in tqdm(iterable=members, total=len(members)):
                    t.extract(member)
            shutil.move(self.ex_name, self.kernel_root)
            return 0
        except tarfile.TarError:
            logger.error("Failed to extract tar kernel archive!")
            return 1

    @staticmethod
    def _purge(p: Path) -> None:
        logger.debug("Purging unclean kernel build environment...")
        shutil.rmtree(p, ignore_errors=True)

    def _fresh_unpack(self, res: dict) -> dict:
        ret = self._unpack_targz()
        return res | {"status": "unpack" if not ret else "error", "assume_dirty": False}

    def _dirty_unpack(self, res: dict) -> dict:
        self._purge(self.kernel_root)
        return self._fresh_unpack(res)

    def _no_unpack(self, res: dict) -> dict:
        if self._is_vmlinux():
            logger.info(f"{self.kernel_root} exists. Skipping unpacking phase...")
            if self.skip_prompts or self._reuse_existing_vmlinux():
                logger.debug(f"Re-using existing {self.kernel_root}/vmlinux")
                return res | {"status": "reuse", "assume_dirty": False}
            else:
                return res | {"status": "unpack", "assume_dirty": True}
        else:
            logger.debug(f"{self.kernel_root} does exist, but contains no kernel. Assuming dirty directory...")
            return res | {"status": "unpack", "assume_dirty": True}

    def run(self) -> dict:
        res = {"kroot": self.kernel_root}
        if not self.kernel_root.exists():
            logger.debug(f"{self.kernel_root} does not exist. Unpacking fresh kernel...")
            return self._fresh_unpack(res)
        elif not self._is_dest_empty():
            return self._no_unpack(res)
        else:
            logger.debug(f"{self.kernel_root} does exist, but is empty. Purging it and unpacking fresh kernel...")
            return self._dirty_unpack(res)
