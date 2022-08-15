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
from src.ctf_runner import CTFRunner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ctf', '-c', action=argparse.BooleanOptionalAction, help='Use this in combination with "--env" in CTF environments where you were given a Linux kernel image and a file system')
    parser.add_argument('--env', '-e', nargs=2, help='Expected: <kernel_image> <root_file_system>')
    args = parser.parse_args()
    if args.ctf and not args.env:
        logger.error('Found --ctf but no environment was specified...')
        logger.error(f'Usage: python3 {Path(__file__).name} --ctf --env <kernel> <rootfs>')
        exit(-1)

    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")

    if args.ctf and args.env:
        logger.info("Executing in CTF context")
        CTFRunner(image=Path(args.env[0]), fs=Path(args.env[1])).run()
    else:
        logger.info("Executing in non-CTF context")

        karchive = KernelDownloader().run()
        if not KernelUnpacker(karchive).run():
            KernelBuilder().run()
        RootFSBuilder().run()

        Debuggee().run()
        tmux("selectp -t 0")
        Debugger().run()
        tmux("selectp -t 0")



if __name__ == "__main__":
    main()
