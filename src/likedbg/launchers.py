"""Wrap the stage-built argv into the shell commands that run in tmux panes: native
QEMU on the host, gdb inside the debugger container. Pure string construction — the
Debuggee/Debugger stages build the argv from the live context and pass it here; the
Session sends the result to a tmux pane."""

from __future__ import annotations

import shlex
from pathlib import Path

from likedbg.constants import VOLUME_MOUNT


def qemu_pane_command(argv: list[str]) -> str:
    # shlex.join shell-quotes each token, so multi-word argv elements (e.g.
    # `-append "console=ttyAMA0 nokaslr ..."`) survive the shell that tmux
    # send-keys feeds the command to, instead of being re-split into args.
    return shlex.join(argv)


def gdb_pane_command(gdb_args: list[str], *, image: str, mount_source: str) -> str:
    docker = (
        f"docker run --rm -it --add-host=host.docker.internal:host-gateway -v {mount_source}:{VOLUME_MOUNT}:ro {image} "
    )
    # Quote the gdb argv too: `-ex "hbreak start_kernel"` must reach gdb as one arg.
    return docker + shlex.join(gdb_args)


def qemu_container_command(
    argv: list[str], *, image: str, ro_mounts: list[Path], rw_mounts: list[Path], gdbstub_port: int = 1234
) -> str:
    # In-container QEMU (x86_64-on-Mac TCG / Linux KVM). Publish the gdbstub to the host so the
    # containerized gdb reaches it at host.docker.internal:1234 (same as native-HVF). Bind each
    # artifact at its identical host path so the QEMU argv's embedded paths resolve unchanged.
    # The kernel Image is read-only (QEMU only reads -kernel); the rootfs disk must be writable
    # (QEMU opens -drive read-write — exactly as the native host process does).
    ro = [f"-v {shlex.quote(str(p))}:{shlex.quote(str(p))}:ro" for p in ro_mounts]
    rw = [f"-v {shlex.quote(str(p))}:{shlex.quote(str(p))}:rw" for p in rw_mounts]
    binds = " ".join(ro + rw)
    docker = f"docker run --rm -it -p {gdbstub_port}:{gdbstub_port} {binds} {image} "
    return docker + shlex.join(argv)
