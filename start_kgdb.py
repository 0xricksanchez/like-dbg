#!/usr/bin/env python3


from loguru import logger

from src.debuggee import Debuggee
from src.debugger import Debugger
from src.kernel_builder import KernelBuilder
from src.kernel_unpacker import KernelUnpacker
from src.linux_kernel_dl import KernelDownloader
from src.misc import tmux, tmux_shell
from src.rootfs_builder import RootFSBuilder


def main():
    tmux("selectp -t 0")
    tmux('rename-window "LIKE-DBG"')
    tmux("splitw -h -p 50")
    tmux("selectp -t 0")
    tmux("splitw -v -p 50")
    tmux("selectp -t 0")

    karchive = KernelDownloader().run()
    if not KernelUnpacker(karchive).run():
        KernelBuilder().run()
    RootFSBuilder().run()

    Debuggee().run()
    tmux("selectp -t 0")
    Debugger().run()
    tmux("selectp -t 0")

    logger.debug("Loaded tmux config")
    tmux_shell("tmux source-file .tmux.conf")


if __name__ == "__main__":
    main()
