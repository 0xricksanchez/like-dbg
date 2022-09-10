#!/usr/bin/env python3

import argparse
import textwrap
from pathlib import Path
import sys
import os
import signal

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


def signal_handler(sig, frame) -> None:
    logger.critical("Received CTRL+C. Shutting down!")
    kill_session()


def kill_session() -> None:
    tmux("selectw -t 'LIKE-DBG'")
    tmux("selectp -t 0")
    try:
        containers = DockerRunner(kroot="foobar").list_running_containers()
        for c in containers:
            if c.status == "running" and next((s for s in c.image.tags if "like_" in s), None):
                c.stop(timeout=0)
                logger.debug(f"Stopped {c.image.tags}")
    except Exception:
        logger.debug("Something went wrong...")
    finally:
        tmux("kill-pane -a -t 0")
        logger.info("Debugging session ended.")
    exit(0)


def stage5(skip: bool, generic_args: dict, dbge_args: dict, dbg_args: dict) -> None:
    if not generic_args["ctf_ctx"]:
        kunpacker = stage4(skip, **generic_args)
    else:
        kunpacker = {}
    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")
    Debuggee(**dbge_args | kunpacker | generic_args).run()
    tmux("selectp -t 0")
    Debugger(**dbg_args | kunpacker | generic_args).run()
    tmux("selectp -t 0")


def stage4(skip: bool, **kwargs) -> dict[str, str]:
    if not skip:
        kunpacker = stage3(skip, **kwargs)
        RootFSBuilder(**kwargs | kunpacker).run()
        return kunpacker
    else:
        RootFSBuilder(**kwargs, kroot="foobar").run()
        return {}


def stage3(skip: bool, **kwargs) -> dict:
    kunpacker = stage2(**kwargs)
    if not kunpacker["status_code"] and not skip:
        KernelBuilder(**kwargs | kunpacker).run()
    else:
        logger.info("Kernel already built. Skipping building phase...")
    return kunpacker


def stage2(**kwargs) -> dict:
    kaname = stage1(**kwargs)
    return KernelUnpacker(kaname, **kwargs).run()


def stage1(**kwargs) -> Path:
    return KernelDownloader(**kwargs).run()


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--config", "-c", required=False, nargs=1, help="Allows providing a custom 'user.ini'")
    parser.add_argument("--ctf", nargs=2, required=False, help="Expected: <kernel_image> <root_file_system>")
    parser.add_argument("--yes", "-y", action=argparse.BooleanOptionalAction, help="If this is set all re-use prompts are answered with 'yes'")
    parser.add_argument("--verbose", "-v", action=argparse.BooleanOptionalAction, help="Enable debug logging")
    parser.add_argument("--kill", "-k", action=argparse.BooleanOptionalAction, help="Completely shutdown current session")
    parser.add_argument(
        "--partial",
        "-p",
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
    return parser.parse_args()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_cli()
    log_level = set_log_level(args.verbose)

    if args.kill:
        kill_session()

    tmux("selectp -t 0")
    tmux('rename-session "LIKE-DBG"')
    tmux('rename-window "LIKE-DBG"')
    generic_args = {
        "skip_prompts": True if args.yes else False,
        "ctf_ctx": True if args.ctf else False,
        "log_level": log_level,
        "user_cfg": args.config[0] if args.config else "",
    }
    dbge_args = {}
    dbg_args = {}

    if args.partial:
        logger.debug("Executing in partial-run context")
        if args.partial == 1:
            stage1()
        elif args.partial == 2:
            stage2(**generic_args)
        elif args.partial == 3:
            stage3(skip=False, **generic_args)
        else:
            stage4(skip=True, **generic_args)
        exit(0)

    if args.ctf:
        logger.debug("Executing in CTF context")
        ctf_kernel = Path(args.ctf[0])
        ctf_fs = Path(args.ctf[1])
        if not ctf_kernel.exists():
            logger.critical(f"Failed to find {ctf_kernel}")
            exit(-1)
        if not ctf_fs.exists():
            logger.critical(f"Failed to find {ctf_fs}")
            exit(-1)
        dbge_args = generic_args | {"ctf_kernel": ctf_kernel, "ctf_fs": ctf_fs}
        dbg_args = {k: v for k, v in dbge_args.items() if k != "ctf_fs"}
        skip = True
    else:
        logger.debug("Executing in non-CTF context")
        skip = False

    stage5(skip, generic_args, dbge_args, dbg_args)


if __name__ == "__main__":
    main()
