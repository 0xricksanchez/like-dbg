"""Foreign-kernel (CTF adopt) host-side logic: arch detection, vmlinux extraction,
initramfs repack, and live console upload. See ADR-0010."""

from __future__ import annotations

import base64
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from typing import Literal

from likedbg.config import ForeignCfg
from likedbg.errors import LikeDbgError

_EM_TO_ARCH = {62: "x86_64", 183: "arm64"}  # EM_X86_64, EM_AARCH64


def _dedup_mounts(specs: list[tuple[str, Path, str, str]]) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Build a docker `volumes` dict deduplicated by host directory, plus the in-container
    path for each spec. `specs` is a list of (bind_pref, host_dir, mode, name) tuples.

    A CTF challenge commonly ships multiple inputs (e.g. initramfs + exploit.c) in the SAME
    host directory. Keying `volumes` naively by host dir (as separate dict literal entries)
    silently collapses duplicate keys and drops a mount. This dedups explicitly: the dir is
    mounted once under the first-seen bind_pref, upgraded to rw if any role sharing it needs
    rw, and every spec's container path is rebased onto whichever bind its dir landed on.
    """
    volumes: dict[str, dict[str, str]] = {}
    cpaths: list[str] = []
    for bind_pref, host_dir, mode, name in specs:
        hd = str(host_dir)
        if hd in volumes:
            if mode == "rw":
                volumes[hd]["mode"] = "rw"
            bind = volumes[hd]["bind"]
        else:
            volumes[hd] = {"bind": bind_pref, "mode": mode}
            bind = bind_pref
        cpaths.append(f"{bind}/{name}")
    return volumes, cpaths


class ForeignError(LikeDbgError):
    """A foreign-kernel adopt/boot/exploit-delivery operation could not be set up."""


@dataclass(frozen=True)
class ForeignKernel:
    image: Path
    vmlinux: Path
    initramfs: Path | None
    arch: str
    cmdline: str


def detect_arch(vmlinux: Path) -> str:
    """Return 'x86_64'/'arm64' from the ELF e_machine, else raise ForeignError."""
    with vmlinux.open("rb") as f:
        head = f.read(20)
    if head[:4] != b"\x7fELF":
        raise ForeignError(
            f"{vmlinux} is not an ELF file (cannot detect arch)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    if len(head) < 20:
        raise ForeignError(
            f"{vmlinux} is too short to be a valid ELF (truncated header)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    endian: Literal["little", "big"] = "little" if head[5] == 1 else "big"
    e_machine = int.from_bytes(head[18:20], endian)
    arch = _EM_TO_ARCH.get(e_machine)
    if arch is None:
        raise ForeignError(
            f"unsupported ELF e_machine {e_machine} in {vmlinux}",
            remedy="set [foreign].arch to x86_64 or arm64",
        )
    return arch


def extract_vmlinux(container: Any, image_path: Path, out: Path, *, image: str) -> Path:
    """Carve an uncompressed vmlinux ELF from a boot image inside the like_musl container.

    Returns `out` on success. Note: a vmlinux carved from a bzImage is fully stripped
    (kallsyms only, no ELF .symtab) — good for arch-detect, but gdb gets no function symbols
    (see ADR-0010). Raises ForeignError if extraction produces no file.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    volumes, (in_path, out_path) = _dedup_mounts(
        [
            ("/in", image_path.parent, "ro", image_path.name),
            ("/out", out.parent, "rw", out.name),
        ]
    )
    c = container.run_detached(image, volumes=volumes, detach=True, tty=True)
    try:
        container.exec(c, f"/opt/extract-vmlinux.sh {shlex.quote(in_path)} {shlex.quote(out_path)}")
    finally:
        container.stop(c)
    if not out.is_file() or out.stat().st_size == 0:
        raise ForeignError(
            f"could not extract vmlinux from {image_path}",
            remedy="provide [foreign].vmlinux explicitly (arm64 Image / unknown compression)",
        )
    return out


def resolve_input_path(workspace: Path, raw: str) -> Path:
    """Absolute paths pass through; relative paths resolve under the workspace."""
    p = Path(raw)
    return p if p.is_absolute() else (workspace / p)


def resolve_foreign(
    container: Any,
    cfg: ForeignCfg,
    workspace: Path,
    *,
    out_dir: Path,
    image: str,
) -> ForeignKernel:
    """Resolve foreign inputs, extract vmlinux if absent, detect arch, return a ForeignKernel.

    Called in cmd_foreign BEFORE resolve_for_run so the detected arch can be injected as a
    cli_override into HostProfile.detect (matching how cmd_use injects the cached build's arch).
    """
    image_path = resolve_input_path(workspace, cfg.image)
    if not image_path.is_file():
        raise ForeignError(
            f"[foreign].image not found: {image_path}",
            remedy="check the path (absolute or workspace-relative)",
        )

    if cfg.vmlinux:
        vmlinux = resolve_input_path(workspace, cfg.vmlinux)
        if not vmlinux.is_file():
            raise ForeignError(f"[foreign].vmlinux not found: {vmlinux}", remedy="check the path")
    else:
        vmlinux = extract_vmlinux(container, image_path, out_dir / "vmlinux", image=image)

    initramfs: Path | None = None
    if cfg.initramfs:
        initramfs = resolve_input_path(workspace, cfg.initramfs)
        if not initramfs.is_file():
            raise ForeignError(f"[foreign].initramfs not found: {initramfs}", remedy="check the path")

    arch = cfg.arch or detect_arch(vmlinux)
    if arch not in ("x86_64", "arm64"):
        raise ForeignError(f"invalid [foreign].arch {arch!r}", remedy="use x86_64 or arm64")

    return ForeignKernel(image=image_path, vmlinux=vmlinux, initramfs=initramfs, arch=arch, cmdline=cfg.cmdline)


_MUSL_GCC = {"x86_64": "x86_64-linux-musl-gcc", "arm64": "aarch64-linux-musl-gcc"}


def _repack_command(in_path: str, src_path: str, arch: str, out_path: str) -> str:
    if arch not in _MUSL_GCC:
        raise ForeignError(f"unsupported foreign arch {arch!r}", remedy="use x86_64 or arm64")
    in_q = shlex.quote(in_path)
    src_q = shlex.quote(src_path)
    out_q = shlex.quote(out_path)
    if src_path.endswith(".c"):
        inject = f"{_MUSL_GCC[arch]} -static {src_q} -o /work/rootfs/exploit"
    else:
        inject = f"cp {src_q} /work/rootfs/exploit && chmod +x /work/rootfs/exploit"
    unpack = f"if gzip -t {in_q} 2>/dev/null; then gzip -dc {in_q} | cpio -idm; else cpio -idm < {in_q}; fi"
    repack = "find . -print0 | cpio --null --format=newc -o --owner=root"
    if out_path.endswith(".gz"):
        repack += f" | gzip -9 > {out_q}"
    else:
        repack += f" > {out_q}"
    return " && ".join(["mkdir -p /work/rootfs", "cd /work/rootfs", unpack, inject, repack])


def repack_initramfs(
    container: Any,
    *,
    initramfs: Path,
    exploit: Path,
    arch: str,
    out: Path,
    image: str,
) -> Path:
    """Unpack the foreign initramfs, inject the exploit at /exploit (musl-static compile of a
    .c, else copy a prebuilt static binary), repack (newc [+gzip]) to `out` in the like_musl
    container. Compiling to the FOREIGN arch is why `arch` is threaded in."""
    out.parent.mkdir(parents=True, exist_ok=True)
    volumes, (in_path, src_path, out_path) = _dedup_mounts(
        [
            ("/in", initramfs.parent, "ro", initramfs.name),
            ("/src", exploit.parent, "ro", exploit.name),
            ("/out", out.parent, "rw", out.name),
        ]
    )
    cmd = _repack_command(in_path, src_path, arch, out_path)
    c = container.run_detached(image, volumes=volumes, detach=True, tty=True)
    try:
        container.exec(c, cmd)
    finally:
        container.stop(c)
    if not out.is_file() or out.stat().st_size == 0:
        raise ForeignError(
            f"initramfs repack produced no output at {out}",
            remedy="check the exploit compiles and the cpio format round-trips",
        )
    return out


_PROBE = "LIKEDBG-PROBE"
_DONE = "LIKEDBG-DONE"


def console_upload(
    session: Any,
    pane: str,
    file: Path,
    *,
    read_console: Callable[[], str],
    chunk: int = 512,
    dest: str = "/tmp/exploit",
) -> None:
    """Best-effort live upload of a SMALL static exploit over the serial console (no reboot).

    Probes for base64 + a writable /tmp (else ForeignError 'use repack'), sends the payload as
    chunked base64 appended to `dest`, then verifies the echoed byte-count + sha256 match.
    Repack (ForeignRepackStage) is the reliable fallback.
    """
    session.send_keys(
        pane,
        f'echo "{_PROBE} base64=$(command -v base64 >/dev/null && echo yes || echo no) '
        f'tmp=$(touch /tmp/.lk && echo yes || echo no)"',
    )
    probe = read_console()
    if "base64=yes" not in probe or "tmp=yes" not in probe:
        raise ForeignError(
            "guest lacks base64 or a writable /tmp for console-upload",
            remedy="use repack (set [foreign].exploit and reboot)",
        )

    data = file.read_bytes()
    session.send_keys(pane, f": > {dest}.b64")
    b64 = base64.b64encode(data).decode()
    for i in range(0, len(b64), chunk):
        session.send_keys(pane, f"printf %s {b64[i : i + chunk]} >> {dest}.b64")
    session.send_keys(pane, f"base64 -d {dest}.b64 > {dest} && chmod +x {dest}")
    session.send_keys(
        pane,
        f"echo \"{_DONE} size=$(wc -c < {dest}) sha=$(sha256sum {dest} | cut -d' ' -f1)\"",
    )

    echoed = read_console().replace("\r\n", "\n")
    want_size = str(len(data))
    want_sha = sha256(data).hexdigest()
    if f"size={want_size}" not in echoed or f"sha={want_sha}" not in echoed:
        raise ForeignError(
            "console-upload verification failed (size/hash mismatch)",
            remedy="chunking corrupted the transfer — retry or use repack",
        )
