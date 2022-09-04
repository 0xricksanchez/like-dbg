#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys
import os

try:
    from loguru import logger

    from src.debuggee import Debuggee
    from src.debugger import Debugger
    from src.kernel_builder import KernelBuilder
    from src.kernel_unpacker import KernelUnpacker
    from src.linux_kernel_dl import KernelDownloader
    from src.misc import tmux
    from src.rootfs_builder import RootFSBuilder
except ModuleNotFoundError:
    if sys.prefix == sys.base_prefix:
        print("-> No active virtual environment found!")
    else:
        print("-> Is the 'requirements.txt' installed?")
    exit(-1)
finally:
    if not os.getenv("TMUX"):
        print("-> Not running inside a TMUX session!")
        exit(-1)


def set_log_level(verbose: bool) -> str:
    logger.remove()
    log_level = "DEBUG" if verbose else "INFO"
    logger.add(sys.stderr, level=log_level)
    return log_level


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
    parser.add_argument("--verbose", "-v", action=argparse.BooleanOptionalAction, help="Enable debug logging")
    args = parser.parse_args()
    log_level = set_log_level(args.verbose)
    if args.ctf and not args.env:
        logger.error("Found --ctf but no environment was specified...")
        logger.error(f"Usage: python3 {Path(__file__).name} --ctf --env <kernel> <rootfs>")
        exit(-1)

    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    kunpacker = {}
    generic_args = {"skip_prompts": True if args.yes else False, "ctf_ctx": True if args.ctf else False, "log_level": log_level}
    dbge_args = {} | generic_args
    dbg_args = {} | generic_args

    if args.ctf and args.env:
        logger.debug("Executing in CTF context")
        ctf_kernel = Path(args.env[0])
        ctf_fs = Path(args.env[1])
        if not ctf_kernel.exists():
            logger.critical(f"Failed to find {ctf_kernel}")
            exit(-1)
        if not ctf_fs.exists():
            logger.critical(f"Failed to find {ctf_fs}")
            exit(-1)
        dbge_args = generic_args | {"ctf_kernel": ctf_kernel, "ctf_fs": ctf_fs}
        dbg_args = {k: v for k, v in dbge_args.items() if k != "ctf_fs"}
    else:
        logger.debug("Executing in non-CTF context")

        kaname = KernelDownloader().run()
        kunpacker = KernelUnpacker(kaname, **generic_args).run()
        if not kunpacker["status_code"]:
            KernelBuilder(**generic_args | kunpacker).run()
        RootFSBuilder(**generic_args | kunpacker).run()

    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")
    Debuggee(**dbge_args | kunpacker).run()
    tmux("selectp -t 0")
    Debugger(**dbg_args | kunpacker).run()
    tmux("selectp -t 0")


if __name__ == "__main__":
    main()
