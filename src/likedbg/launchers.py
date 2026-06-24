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


def gdb_pane_command(gdb_args: list[str], *, image: str, mount_source: str, network_mode: str = "published") -> str:
    # Host net (Linux): gdb reaches QEMU on localhost. Published (macOS): the host-gateway alias
    # resolves host.docker.internal to the published gdbstub port.
    net = "--network host" if network_mode == "host" else "--add-host=host.docker.internal:host-gateway"
    docker = f"docker run --rm -it {net} -v {mount_source}:{VOLUME_MOUNT}:ro {image} "
    # Quote the gdb argv too: `-ex "hbreak start_kernel"` must reach gdb as one arg.
    return docker + shlex.join(gdb_args)


def qemu_container_command(
    argv: list[str],
    *,
    image: str,
    ro_mounts: list[Path],
    rw_mounts: list[Path],
    gdbstub_port: int = 1234,
    network_mode: str = "published",
    kvm: bool = False,
) -> str:
    # In-container QEMU. Bind each artifact at its identical host path so the argv's embedded
    # paths resolve unchanged (kernel :ro, rootfs disk :rw). Network mode: host net (Linux,
    # gdb→localhost) or a published gdbstub port (macOS / forced, gdb→host.docker.internal).
    q = shlex.quote
    ro = [f"-v {q(str(p))}:{q(str(p))}:ro" for p in ro_mounts]
    rw = [f"-v {q(str(p))}:{q(str(p))}:rw" for p in rw_mounts]
    binds = " ".join(ro + rw)
    net = "--network host" if network_mode == "host" else f"-p {gdbstub_port}:{gdbstub_port}"
    dev = " --device /dev/kvm" if kvm else ""
    docker = f"docker run --rm -it {net}{dev} {binds} {image} "
    return docker + shlex.join(argv)
