#!/usr/bin/env python3

import argparse
import textwrap
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
    from src.docker_runner import DockerRunner
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


def kill_session() -> None:
    tmux("selectw -t 'LIKE-DBG'")
    tmux("selectp -t 0")
    containers = DockerRunner(kroot="foobar").list_running_containers()
    for c in containers:
        if c.status == "running" and next((s for s in c.image.tags if "like_" in s), None):
            c.stop(timeout=0)
            logger.debug(f"Stopped {c.image.tags}")
    tmux("kill-pane -a -t 0")
    logger.info("Debugging session ended.")
    exit(0)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "--ctf",
        "-c",
        action=argparse.BooleanOptionalAction,
        help='Use this in combination with "--env" in CTF environments where you were given a Linux kernel image and a file system',
    )
    parser.add_argument("--env", "-e", nargs=2, help="Expected: <kernel_image> <root_file_system>")
    parser.add_argument("--yes", "-y", action=argparse.BooleanOptionalAction, help="If this is set all re-use prompts are answered with 'yes'")
    parser.add_argument("--verbose", "-v", action=argparse.BooleanOptionalAction, help="Enable debug logging")
    parser.add_argument("--kill", "-k", action=argparse.BooleanOptionalAction, help="Completely shutdown current session")
    parser.add_argument(
        "--dry",
        "-d",
        type=int,
        choices=range(1, 5),
        help=textwrap.dedent(
            """\
    Stage 1 - Kernel download only,
    Stage 2 - Stage 1 & unpacking,
    Stage 3 - Stage 2 & building,
    Stage 4 - RootFS building only.
    """
        ),
    )
    args = parser.parse_args()
    log_level = set_log_level(args.verbose)

    if args.kill:
        kill_session()

    if args.ctf and not args.env:
        logger.error("Found --ctf but no environment was specified...")
        logger.error(f"Usage: python3 {Path(__file__).name} --ctf --env <kernel> <rootfs>")
        exit(-1)

    tmux("selectp -t 0")
    tmux('rename-session "LIKE-DBG"')
    tmux('rename-window "LIKE-DBG"')
    kunpacker = {}
    generic_args = {"skip_prompts": True if args.yes else False, "ctf_ctx": True if args.ctf else False, "log_level": log_level}
    dbge_args = {} | generic_args
    dbg_args = {} | generic_args

    if args.dry:
        logger.debug("Executing in dry-run context")
        if args.dry == 1:
            stage1()
        elif args.dry == 2:
            stage2(**generic_args)
        elif args.dry == 3:
            stage3(**generic_args)
        else:
            stage4(**generic_args, skip=True)
        exit(0)


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
        stage4(**generic_args, skip=False)

    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")
    Debuggee(**dbge_args | kunpacker).run()
    tmux("selectp -t 0")
    Debugger(**dbg_args | kunpacker).run()
    tmux("selectp -t 0")


def stage4(**kwargs, skip:bool = False) -> None:
    kunpacker = stage3(**kwargs, skip)
    RootFSBuilder(**kwargs | kunpacker)

def stage3(**kwargs, skip:bool = False) -> None:
    kunpacker = stage2(**kwargs)
    if not kunpacker["status_code"] and not skip:
        KernelBuilder(**kwargs | kunpacker)
    return kunpacker


def stage2(**kwargs) -> dict:
    kaname = stage1()
    return KernelUnpacker(kaname, **kwargs).run()


def stage1() -> str:
    return KernelDownloader().run()



if __name__ == "__main__":
    main()
