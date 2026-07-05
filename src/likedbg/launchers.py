"""Wrap the stage-built argv into the shell commands that run in tmux panes: native
QEMU on the host, gdb inside the debugger container. Pure string construction — the
Debuggee/Debugger stages build the argv from the live context and pass it here; the
Session sends the result to a tmux pane."""

from __future__ import annotations

import shlex
from pathlib import Path

from likedbg.constants import CRASH_DROP_MOUNT
from likedbg.constants import VOLUME_MOUNT


def qemu_pane_command(argv: list[str]) -> str:
    # shlex.join shell-quotes each token, so multi-word argv elements (e.g.
    # `-append "console=ttyAMA0 nokaslr ..."`) survive the shell that tmux
    # send-keys feeds the command to, instead of being re-split into args.
    return shlex.join(argv)


def gdb_pane_command(
    gdb_args: list[str],
    *,
    image: str,
    mount_source: str,
    network_mode: str = "published",
    crash_drop: Path | None = None,
) -> str:
    # Host net (Linux): gdb reaches QEMU on localhost. Published (macOS): the host-gateway alias
    # resolves host.docker.internal to the published gdbstub port.
    net = "--network host" if network_mode == "host" else "--add-host=host.docker.internal:host-gateway"
    crash = f"-v {shlex.quote(str(crash_drop))}:{CRASH_DROP_MOUNT}:rw " if crash_drop is not None else ""
    docker = f"docker run --rm -it {net} -v {mount_source}:{VOLUME_MOUNT}:ro {crash}{image} "
    # Quote the gdb argv too: `-ex "hbreak start_kernel"` must reach gdb as one arg.
    return docker + shlex.join(gdb_args)


def qemu_container_command(
    argv: list[str],
    *,
    image: str,
    ro_mounts: list[Path],
    rw_mounts: list[Path],
    gdbstub_port: int = 1234,
    ssh_port: int | None = None,
    network_mode: str = "published",
    kvm: bool = False,
    extra_rw_dirs: tuple[Path, ...] = (),
) -> str:
    # In-container QEMU. Bind each artifact at its identical host path so the argv's embedded
    # paths resolve unchanged (kernel :ro, rootfs disk :rw). Network mode: host net (Linux,
    # gdb→localhost) or a published gdbstub port (macOS / forced, gdb→host.docker.internal).
    q = shlex.quote
    mounts = [f"-v {q(str(p))}:{q(str(p))}:ro" for p in ro_mounts]
    mounts += [f"-v {q(str(p))}:{q(str(p))}:rw" for p in rw_mounts]
    mounts += [f"-v {q(str(d))}:{q(str(d))}:rw" for d in extra_rw_dirs]
    net = "--network host" if network_mode == "host" else f"-p {gdbstub_port}:{gdbstub_port}"
    parts = ["docker run --rm -it", net, *mounts]
    if ssh_port is not None and network_mode != "host":
        parts.append(f"-p {ssh_port}:{ssh_port}")
    if kvm:
        parts.append("--device /dev/kvm")
    parts.append(image)
    docker = " ".join(parts) + " "
    return docker + shlex.join(argv)
