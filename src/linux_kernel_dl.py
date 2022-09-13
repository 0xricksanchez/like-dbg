#!/usr/bin/env python3

import re
import urllib.request
from pathlib import Path

import requests
from loguru import logger

from .misc import cfg_setter
from .tqdm_dlbar import DLProgressBarTQDM


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | KERNEL DOWNLOADER                                                                                   |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class KernelDownloader:
    def __init__(self, **kwargs) -> None:
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["kernel_dl"], user_cfg)
        self.commit = self._set_commit()
        self.choice = self._set_choice()
        logger.info(f"Using kernel with (tag/commit/version) {self.choice}")
        self.dl_uri = self._set_dl_uri()
        if not Path(self.kernel_dl_path).exists():
            Path(self.kernel_dl_path).mkdir()
        self.archive = Path(self.kernel_dl_path) / f"linux-{self.choice}.tar.gz"
        logger.debug(f"Kernel snap: {self.dl_uri}")

    def _set_commit(self):
        if any([self.tag, self.mmp]):
            return self.commit
        elif self.commit:
            return self.commit
        else:
            return self._resolve_latest()

    def _resolve_latest(self) -> str:
        commit_re = rb"commit\/\?id=[0-9a-z]*"
        r = requests.get(self.commit_uri)
        search_res = re.search(commit_re, r.content)
        if search_res.group():
            commit = search_res.group().split(b"=")[1].decode()
            logger.debug(f"Found latest commit: {commit}")
            return commit
        else:
            logger.critical("Resolving latest commit")
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
            (major, minor, patch) = tuple(self.mmp.split("."))
            self.mmp_uri = self.mmp_uri.replace("KMAJOR", major)
            self.mmp_uri = self.mmp_uri.replace("KMINOR", minor)
            self.mmp_uri = self.mmp_uri.replace("KPATCH", patch)
            return self.mmp_uri
        else:
            return f"{self.snap_uri}{self.choice}.tar.gz"

    def is_present(self) -> bool:
        if Path(self.archive).exists():
            logger.info("Kernel archive already exists locally. Skipping downloading phase...")
            return True
        else:
            return False

    def download_kernel_archive(self) -> None:
        logger.info(f"Downloading {self.dl_uri}... This may take a while!")
        with DLProgressBarTQDM(unit="B", unit_scale=True, miniters=1, desc=self.archive.name) as t:
            urllib.request.urlretrieve(self.dl_uri, filename=self.archive, reporthook=t.update_to)
            t.total = t.n

    def run(self) -> Path:
        if not self.is_present():
            self.download_kernel_archive()
        return self.archive
