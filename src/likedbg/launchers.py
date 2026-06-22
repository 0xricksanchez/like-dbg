"""Wrap the stage-built argv into the shell commands that run in tmux panes: native
QEMU on the host, gdb inside the debugger container. Pure string construction — the
Debuggee/Debugger stages build the argv from the live context and pass it here; the
Session sends the result to a tmux pane."""

from __future__ import annotations


def qemu_pane_command(argv: list[str]) -> str:
    return " ".join(argv)


def gdb_pane_command(gdb_args: list[str], *, image: str, kernel_volume: str) -> str:
    docker = f"docker run --rm -it --add-host=host.docker.internal:host-gateway -v {kernel_volume}:/ksrc:ro {image} "
    return docker + " ".join(gdb_args)
