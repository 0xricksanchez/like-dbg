#!/usr/bin/env python3

import argparse
from pathlib import Path

from loguru import logger

from src.debuggee import Debuggee
from src.debugger import Debugger
from src.kernel_builder import KernelBuilder
from src.kernel_unpacker import KernelUnpacker
from src.linux_kernel_dl import KernelDownloader
from src.misc import tmux
from src.rootfs_builder import RootFSBuilder


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ctf",
        "-c",
        action=argparse.BooleanOptionalAction,
        help='Use this in combination with "--env" in CTF environments where you were given a Linux kernel image and a file system',
    )
    parser.add_argument("--env", "-e", nargs=2, help="Expected: <kernel_image> <root_file_system>")
    parser.add_argument("--yes", "-y", action=argparse.BooleanOptionalAction, help="If this is set all re-use prompts are answered with 'yes'")
    args = parser.parse_args()
    if args.ctf and not args.env:
        logger.error("Found --ctf but no environment was specified...")
        logger.error(f"Usage: python3 {Path(__file__).name} --ctf --env <kernel> <rootfs>")
        exit(-1)

    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    generic_args = {"skip_prompts": True if args.yes else False}
    dbge_args = {} | generic_args
    dbg_args = {} | generic_args

    if args.ctf and args.env:
        logger.info("Executing in CTF context")
        ctf_kernel = Path(args.env[0])
        ctf_fs = Path(args.env[1])
        if not ctf_kernel.exists():
            logger.error(f"Failed to find {ctf_kernel}")
            exit(-1)
        if not ctf_fs.exists():
            logger.error(f"Failed to find {ctf_fs}")
            exit(-1)
        dbge_args = generic_args | {"ctf_ctx": True if args.ctf else False, "ctf_kernel": ctf_kernel, "ctf_fs": ctf_fs}
        dbg_args = {k: v for k, v in dbge_args.items() if k != "ctf_fs"}
    else:
        logger.info("Executing in non-CTF context")

        karchive = KernelDownloader().run()
        if not KernelUnpacker(karchive, **generic_args).run():
            KernelBuilder(**generic_args).run()
        RootFSBuilder(**generic_args).run()

    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")
    Debuggee(**dbge_args).run()
    tmux("selectp -t 0")
    Debugger(**dbg_args).run()
    tmux("selectp -t 0")


if __name__ == "__main__":
    main()
