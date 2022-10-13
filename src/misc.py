#!/usr/bin/env python3

import configparser
import hashlib
import os
import subprocess as sp
from contextlib import contextmanager
from pathlib import Path
from sys import stdin
from termios import TCIFLUSH, tcflush

from loguru import logger

SYSTEM_CFG = Path.cwd() / "configs" / "system.ini"
USER_CFG = Path.cwd() / "configs" / "user.ini"
CFGS = [SYSTEM_CFG, USER_CFG]


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | MISC QOL functions                                                                                  |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
def cfg_setter(obj, sections: list[str], user_cfg: str, exclude_keys: list[str] = [], cherry_pick: dict[str, list[str]] = {}) -> None:
    global CFGS
    cfgs = list(CFGS)
    cfg = configparser.ConfigParser()
    ignore_empty = False
    if user_cfg and Path(user_cfg).exists():
        cfgs.append(Path(user_cfg).absolute())
    for c in cfgs:
        if Path(user_cfg).name == c.name:
            ignore_empty = True
        cfg.read(c)
        _set_base_cfg(cfg, exclude_keys, obj, sections, ignore_empty)
        if cherry_pick:
            _cherry_pick(cfg, cherry_pick, obj, ignore_empty)


def _set_base_cfg(cfg, exclude_keys, obj, sections, ignore_empty) -> None:
    for sect in sections:
        if sect not in cfg:
            continue
        for key in cfg[sect]:
            if key not in exclude_keys:
                _set_cfg(cfg, obj, sect, key, ignore_empty)


def _cherry_pick(cfg, cherry_pick, obj, ignore_empty) -> None:
    for sect in cherry_pick.keys():
        if sect not in cfg:
            continue
        for key in cfg[sect]:
            if key in cherry_pick[sect]:
                _set_cfg(cfg, obj, sect, key, ignore_empty)


def _set_cfg(cfg, obj, sect, key, ignore_empty) -> None:
    tmp = cfg[sect][key]
    if ignore_empty and not tmp:
        return
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


def cross_compile(arch: str) -> str:
    if arch == "arm64":
        return "aarch64-linux-gnu-"
    elif arch == "riscv64":
        return "riscv64-linux-gnu-"
    else:
        return "x86_64-pc-linux-gnu-"


def adjust_toolchain_arch(arch: str) -> str:
    if arch == "arm64":
        return "aarch64"
    elif arch == "x86_64":
        return "x86-64"
    else:
        return arch


def adjust_arch(arch: str) -> str:
    if arch == "riscv64":
        return "riscv"
    elif arch in ["x86_64", "arm64"]:
        return arch
    else:
        logger.error("Unknown arch")
        exit(-1)


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


def get_sha256_from_file(p: Path) -> str:
    content = Path(p).read_bytes()
    return hashlib.sha256(content).hexdigest()
