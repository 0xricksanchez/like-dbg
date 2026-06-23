"""Wrap the stage-built argv into the shell commands that run in tmux panes: native
QEMU on the host, gdb inside the debugger container. Pure string construction — the
Debuggee/Debugger stages build the argv from the live context and pass it here; the
Session sends the result to a tmux pane."""

from __future__ import annotations

import shlex


def qemu_pane_command(argv: list[str]) -> str:
    # shlex.join shell-quotes each token, so multi-word argv elements (e.g.
    # `-append "console=ttyAMA0 nokaslr ..."`) survive the shell that tmux
    # send-keys feeds the command to, instead of being re-split into args.
    return shlex.join(argv)


def gdb_pane_command(gdb_args: list[str], *, image: str, mount_source: str) -> str:
    docker = f"docker run --rm -it --add-host=host.docker.internal:host-gateway -v {mount_source}:/ksrc:ro {image} "
    # Quote the gdb argv too: `-ex "hbreak start_kernel"` must reach gdb as one arg.
    return docker + shlex.join(gdb_args)
