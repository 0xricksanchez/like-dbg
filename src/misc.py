#!/usr/bin/env python3

import configparser
import os
import subprocess as sp
from contextlib import contextmanager
from pathlib import Path
from sys import stdin
from termios import tcflush, TCIFLUSH
from typing import List

from loguru import logger

config = Path.cwd() / "config.ini"


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | MISC QOL functions                                                                                  |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
def cfg_setter(obj, sections: List[str]) -> None:
    cfg = configparser.ConfigParser()
    cfg.read(config)
    for sect in sections:
        for key in cfg[sect]:
            tmp = cfg[sect][key]
            val = tmp if tmp not in ["yes", "no"] else cfg[sect].getboolean(key)
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


def canadian_cross(arch: str) -> str:
    if arch == "arm64":
        return "aarch64-linux-gnu-"
    else:
        return "x86_64-pc-linux-gnu-"


def adjust_arch(arch: str) -> str:
    if arch == "arm64":
        return "aarch64"
    elif arch == "x86_64":
        return "x86-64"
    else:
        return arch


def adjust_qemu_arch(arch: str) -> str:
    if arch == "arm64":
        return "aarch64"
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
