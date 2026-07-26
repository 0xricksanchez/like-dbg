"""Foreign-kernel (CTF adopt) host-side logic: arch detection, vmlinux extraction,
initramfs repack, and live console upload. See ADR-0010."""

from __future__ import annotations

import base64
import json
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from typing import Literal

from loguru import logger

from likedbg import images
from likedbg.config import ForeignCfg
from likedbg.config import load_config
from likedbg.constants import LIKEDBG_ZIG_CACHE_VOLUME
from likedbg.constants import MUSL_IMAGE
from likedbg.constants import V2E_VERSION
from likedbg.constants import ZIG_CACHE_MOUNT
from likedbg.errors import ContainerError
from likedbg.errors import LikeDbgError

_EM_TO_ARCH = {62: "x86_64", 183: "arm64"}  # EM_X86_64, EM_AARCH64

# Kallsyms recovery trust gate: a real x86_64 kernel symtab has tens of thousands of symbols with
# `_stext` in the top-of-VA kernel text range; a wrong-base or garbage recovery fails one of these.
_V2E_MIN_SYMBOLS = 1000
_X86_KTEXT_LO = 0xFFFFFFFF80000000


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


@dataclass(frozen=True)
class RecoveryResult:
    ok: bool
    reason: str
    symbol_count: int


def _elf_magic(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_x86_bzimage(image_path: Path) -> bool:
    """True if the boot image is an x86 bzImage (the boot-protocol 'HdrS' magic at offset 0x202).
    Kallsyms recovery is x86-only this round; an arm64 Image has no such header, so it falls through
    to the decompress-only carve / today's behavior (arm64 recovery is a follow-up, see ADR-0015)."""
    try:
        with image_path.open("rb") as f:
            f.seek(0x202)
            return f.read(4) == b"HdrS"
    except OSError:
        return False


def _trust_gate(nm_output: str) -> tuple[bool, str, int]:
    """Decide whether a recovered vmlinux's symbol table is trustworthy enough to hand gdb. A
    confidently-wrong recovery (garbage, or a wrong guessed base that offsets every symbol) is worse
    than no symbols, so accept only a real kernel symtab. Returns (ok, reason, symbol_count)."""
    lines = [ln for ln in nm_output.splitlines() if ln.strip()]
    count = len(lines)
    if count < _V2E_MIN_SYMBOLS:
        return False, f"thin symtab ({count} symbols)", count
    stext_addr: int | None = None
    for ln in lines:
        parts = ln.split()
        # nm line is "<addr> <type> <name>"; an undefined symbol (type U) has no address.
        if len(parts) >= 3 and parts[-1] == "_stext":
            try:
                stext_addr = int(parts[0], 16)
            except ValueError:
                stext_addr = None
            break
    if stext_addr is None:
        return False, "no _stext", count
    if stext_addr < _X86_KTEXT_LO:
        return False, f"_stext out of range (0x{stext_addr:x})", count
    return True, "", count


def recover_vmlinux(container: Any, image_path: Path, out: Path, *, image: str) -> RecoveryResult:
    """Attempt kallsyms symbol recovery on an x86 bzImage: run vmlinux-to-elf in the like_musl
    container, then validate its symtab through _trust_gate. Writes `out` iff a candidate ELF was
    produced (it may exist yet fail the gate). Never raises; a failure returns ok=False so the
    caller can fall back."""
    if not _is_x86_bzimage(image_path):
        return RecoveryResult(ok=False, reason="not an x86 bzImage", symbol_count=0)
    out.parent.mkdir(parents=True, exist_ok=True)
    volumes, (in_path, out_path) = _dedup_mounts(
        [("/in", image_path.parent, "ro", image_path.name), ("/out", out.parent, "rw", out.name)]
    )
    c = container.run_detached(image, volumes=volumes, detach=True, tty=True)
    nm_output: str | None = None
    try:
        container.exec(c, f"vmlinux-to-elf {shlex.quote(in_path)} {shlex.quote(out_path)}")
        if _elf_magic(out):
            nm_output = container.exec(c, f"nm {shlex.quote(out_path)}").output
    except ContainerError:
        nm_output = None
    finally:
        container.stop(c)
    if nm_output is None:
        return RecoveryResult(ok=False, reason="vmlinux-to-elf produced no usable ELF", symbol_count=0)
    ok, reason, count = _trust_gate(nm_output)
    return RecoveryResult(ok=ok, reason=reason, symbol_count=count)


def _carve_vmlinux(container: Any, image_path: Path, out: Path, *, image: str) -> Path:
    """Decompress-only carve (the kernel's own extract-vmlinux.sh): recovers a stripped vmlinux,
    good for arch-detect but no function symbols. Raises ForeignError if it produces no file."""
    out.parent.mkdir(parents=True, exist_ok=True)
    volumes, (in_path, out_path) = _dedup_mounts(
        [("/in", image_path.parent, "ro", image_path.name), ("/out", out.parent, "rw", out.name)]
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


def _file_sha256(path: Path) -> str:
    """Content hash of one file, streamed. Used for every Stamp input that is a file:
    kernel images, initramfs archives, and exploit sources."""
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_stamp(stamp: Path) -> dict[str, str] | None:
    try:
        data = json.loads(stamp.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


# A Stamp records the inputs one derived artifact was last built from (CONTEXT.md -> Stamp).
# Keys are checked in THIS order so the reported reason names the most salient change: identity
# first, then content, then the surrounding build inputs. `command_sha` is deliberately last --
# it is the catch-all that fires when like-dbg's own build command changed, and its message is
# the least specific of the six.
_STAMP_REASONS: dict[str, str] = {
    "exploit_name": "exploit changed",
    "exploit_sha256": "source changed",
    "exploit_flags": "exploit_flags changed",
    "initramfs_sha256": "base initramfs changed",
    "musl_image_sha": "like_musl toolchain image changed",
    "command_sha": "build recipe changed",
}


def _abbrev(key: str, value: str | None) -> str:
    """Shorten hash-valued Stamp fields so a reason line stays readable in the boot log."""
    if value is None:
        return "none"
    return value[:8] if key.endswith(("_sha256", "_sha")) and len(value) > 8 else value


def _stamp_verdict(stamp: Path, out: Path, inputs: dict[str, str], *, force: bool) -> str | None:
    """None -> `out` is a valid cache hit for `inputs`; else a human-readable reason to rebuild.

    Returns the reason rather than a bool so the caller can log WHICH input moved instead of
    silently redoing the work. Fails safe in every ambiguous case -- absent output, absent or
    unreadable Stamp, a key the stored Stamp predates -- so the answer is "rebuild", never "reuse".
    """
    if force:
        return "--force-rebuild"
    if not out.is_file() or out.stat().st_size == 0:
        return "no cached output"
    cached = _read_stamp(stamp)
    if cached is None:
        return "no build record"
    for key, label in _STAMP_REASONS.items():
        if key not in inputs:
            continue
        old = cached.get(key)
        if old != inputs[key]:
            return f"{label}: {_abbrev(key, old)} -> {_abbrev(key, inputs[key])}"
    return None


def musl_image_sha(workspace: Path) -> str:
    """Content hash of the like_musl image's build inputs -- the compiler identity behind an
    exploit build, and the one thing a hash of the build command cannot see (same command, newer
    zig inside the image). Reuses the hash `images.ensure_current` already computes, so this is a
    few file reads and no Docker call.

    Best-effort: "" when the build files are absent, so a stripped-down workspace degrades to
    "toolchain identity not tracked" rather than failing the boot.
    """
    spec = next((s for s in images.IMAGES if s.tag == MUSL_IMAGE), None)
    if spec is None:
        return ""
    try:
        return images.input_sha(spec, workspace)
    except OSError:
        return ""


def extract_vmlinux(container: Any, image_path: Path, out: Path, *, image: str, force: bool = False) -> Path:
    """Resolve a vmlinux for an adopted kernel, best symbols first: reuse a cached result, else
    recover kernel symbols from the bzImage's kallsyms (x86, vmlinux-to-elf in like_musl), else fall
    back to a decompress-only carve (arch-detect only). The outcome is cached under out.stamp
    (keyed by image hash + pinned vmlinux-to-elf version) and logged. Raises ForeignError only when
    nothing produces an ELF (arm64 Image / exotic packing). See ADR-0015.

    `force` (from --force-rebuild) ignores the cached result."""
    out.parent.mkdir(parents=True, exist_ok=True)
    stamp = out.parent / (out.name + ".stamp")
    image_hash = _file_sha256(image_path)

    cached = _read_stamp(stamp)
    if (
        not force
        and out.is_file()
        and cached is not None
        and cached.get("image_sha256") == image_hash
        and cached.get("v2e_version") == V2E_VERSION
    ):
        logger.info(f"foreign vmlinux: reusing cached {cached.get('state', '?')} symbols ({out})")
        return out

    rec = recover_vmlinux(container, image_path, out, image=image)
    if rec.ok:
        state = "RECOVERED"
        logger.info(f"foreign vmlinux: recovered {rec.symbol_count} symbols from kallsyms")
    else:
        _carve_vmlinux(container, image_path, out, image=image)  # raises ForeignError if nothing carves
        state = "DECOMPRESSED"
        logger.warning(
            f"foreign vmlinux: kallsyms recovery failed ({rec.reason}), no kernel symbols; "
            "set [foreign] vmlinux to supply them"
        )
    stamp.write_text(json.dumps({"image_sha256": image_hash, "v2e_version": V2E_VERSION, "state": state}))
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
    force: bool = False,
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
        vmlinux = extract_vmlinux(container, image_path, out_dir / "vmlinux", image=image, force=force)

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


def _musl_compile(arch: str, src_q: str, out_q: str, extra_flags: tuple[str, ...] = ()) -> str:
    """The musl-static cross-compile command fragment (shared by repack + compile_exploit).
    `extra_flags` are the user's [build] exploit_flags; they are quoted here and placed AFTER the
    source so libraries (-l...) resolve in link order (musl folds pthread/rt/dl into libc, so most
    are no-ops, but a challenge's verbatim build line still works). `src_q`/`out_q` arrive quoted.

    Reliable on native Linux; on Docker Desktop for macOS the LinuxKit VM's virtualized filesystem
    intermittently fails zig's from-source musl-build cache check ('CacheCheckFailed') for libc-heavy
    programs (e.g. pthread) - a Mac-only quirk, see docs/ctf-foreign-kernel.md and ADR-0016."""
    if arch not in _MUSL_GCC:
        raise ForeignError(f"unsupported arch {arch!r}", remedy="use x86_64 or arm64")
    flags = "".join(f" {shlex.quote(f)}" for f in extra_flags)
    # ZIG_GLOBAL_CACHE_DIR points zig at the persistent named volume so the from-source musl
    # libc.a is built once and reused (cold ~20s, warm ~1-2s). See ADR-0016 / the Part A gate.
    return f"ZIG_GLOBAL_CACHE_DIR={ZIG_CACHE_MOUNT} {_MUSL_GCC[arch]} -static {src_q}{flags} -o {out_q}"


def compile_exploit(
    container: Any, *, src: Path, arch: str, out: Path, image: str, extra_flags: tuple[str, ...] = ()
) -> Path:
    """Cross-compile a single `.c` to a static musl binary for `arch` in the like_musl container,
    with the user's [build] exploit_flags. Raises ForeignError on an unknown arch or if no output is
    produced.

    Paths are resolved to ABSOLUTE before mounting: a relative host path (e.g. `--run exploit/x.c`)
    would be treated by Docker as a NAMED VOLUME, not a bind mount, so `/src/<file>` would not exist
    and the compile fails opaquely (the x86 live gate surfaced this as zig 'CacheCheckFailed')."""
    src = src.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out = out.resolve()
    volumes, (src_path, out_path) = _dedup_mounts(
        [("/src", src.parent, "ro", src.name), ("/out", out.parent, "rw", out.name)]
    )
    volumes[LIKEDBG_ZIG_CACHE_VOLUME] = {"bind": ZIG_CACHE_MOUNT, "mode": "rw"}
    cmd = _musl_compile(arch, shlex.quote(src_path), shlex.quote(out_path), extra_flags)
    t0 = time.monotonic()
    c = container.run_detached(image, volumes=volumes, detach=True, tty=True)
    try:
        container.exec(c, cmd)
    finally:
        container.stop(c)
    if not out.is_file() or out.stat().st_size == 0:
        raise ForeignError(
            f"exploit compile produced no output at {out}",
            remedy="check the .c compiles static-musl (a single flag-less .c; else pass a prebuilt binary)",
        )
    logger.info(f"exploit: compiled {src.name} in {time.monotonic() - t0:.1f}s")
    return out


def exploit_flags_for(workspace: Path) -> tuple[str, ...]:
    """The user's [build] exploit_flags, or () when the workspace has no project config -- the
    --run/--upload paths are config-optional (they read only the run's host.json/run.json), so a
    missing config must not make them fail; a present-but-malformed config still errors via load_config."""
    if not (workspace / "configs" / "default.toml").exists():
        return ()
    return load_config(workspace).settings.build.exploit_flags


def _repack_command(in_path: str, src_path: str, arch: str, out_path: str, extra_flags: tuple[str, ...] = ()) -> str:
    """The unpack + inject + repack command run in the like_musl container.

    `set -o pipefail` guards the REPACK pipeline: `cpio -o | gzip -1 > out` otherwise reports
    GZIP's status, so a cpio that died partway would still exit 0 having compressed the partial
    stream -- a short but non-empty, and perfectly VALID gzip (so `gzip -t` proves nothing),
    initramfs that passes repack_initramfs's non-empty check, gets Stamped, and is then reused
    forever. The image's /bin/sh is dash 0.5.12, which has pipefail (POSIX 2024).

    It is enabled as its own link of the `&&` chain (never a leading `;`, so a shell WITHOUT
    pipefail dies loudly here rather than running on with the status masked) placed AFTER the
    unpack -- do not "tidy" it to the head of the chain. The unpack's `gzip -dc IN | cpio -idm`
    must keep its default semantics: a zero-PADDED cpio archive is the normal result of
    block-aligning an initramfs, `cpio -idm` stops at the trailer and never reads the padding, so
    gzip takes SIGPIPE and exits 141 on a perfectly good unpack. Under pipefail that kills the
    chain and a working challenge stops booting. Nothing is lost by scoping it: cpio is already
    last in the unpack pipeline, so the status that matters there propagates on its own.
    """
    in_q = shlex.quote(in_path)
    src_q = shlex.quote(src_path)
    out_q = shlex.quote(out_path)
    if src_path.endswith(".c"):
        inject = _musl_compile(arch, src_q, "/work/rootfs/exploit", extra_flags)
    else:
        inject = f"cp {src_q} /work/rootfs/exploit && chmod +x /work/rootfs/exploit"
    unpack = f"if gzip -t {in_q} 2>/dev/null; then gzip -dc {in_q} | cpio -idm; else cpio -idm < {in_q}; fi"
    repack = "find . -print0 | cpio --null --format=newc -o --owner=root"
    if out_path.endswith(".gz"):
        repack += f" | gzip -1 > {out_q}"
    else:
        repack += f" > {out_q}"
    return " && ".join(["mkdir -p /work/rootfs", "cd /work/rootfs", unpack, inject, "set -o pipefail", repack])


def repack_initramfs(
    container: Any,
    *,
    initramfs: Path,
    exploit: Path,
    arch: str,
    out: Path,
    image: str,
    workspace: Path,
    extra_flags: tuple[str, ...] = (),
    force: bool = False,
) -> Path:
    """Unpack the foreign initramfs, inject the exploit at /exploit (musl-static compile of a
    .c with the user's [build] exploit_flags, else copy a prebuilt static binary), repack
    (newc [+gzip]) to `out` in the like_musl container. Compiling to the FOREIGN arch is why
    `arch` is threaded in.

    Stamp-guarded (CONTEXT.md -> Stamp): a call whose exploit, base initramfs, flags, toolchain
    image and build command all match the previous one returns `out` without starting a
    container, so rebooting only to change a runtime mitigation costs nothing. `force` (from
    --force-rebuild) ignores the Stamp.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    volumes, (in_path, src_path, out_path) = _dedup_mounts(
        [
            ("/in", initramfs.parent, "ro", initramfs.name),
            ("/src", exploit.parent, "ro", exploit.name),
            ("/out", out.parent, "rw", out.name),
        ]
    )
    volumes[LIKEDBG_ZIG_CACHE_VOLUME] = {"bind": ZIG_CACHE_MOUNT, "mode": "rw"}
    cmd = _repack_command(in_path, src_path, arch, out_path, extra_flags)

    # Hashed BEFORE the compile, and that same value is stamped below. Re-reading afterwards
    # would record a source the repacked binary was NOT built from if the file changed
    # mid-run -- permanently stale and silent. Hashing first fails toward a spurious rebuild.
    exploit_sha = _file_sha256(exploit)
    stamp = out.parent / (out.name + ".stamp")
    inputs = {
        "exploit_name": exploit.name,
        "exploit_sha256": exploit_sha,
        "exploit_flags": " ".join(extra_flags),
        "initramfs_sha256": _file_sha256(initramfs),
        "musl_image_sha": musl_image_sha(workspace),
        # Hashing the command itself catches any change to like-dbg's own repack logic with no
        # version constant to remember to bump. It also subsumes `arch`, correctly: arch appears
        # in the .c branch's cross-gcc name and is genuinely absent from the prebuilt `cp` branch.
        "command_sha": sha256(cmd.encode()).hexdigest(),
    }
    reason = _stamp_verdict(stamp, out, inputs, force=force)
    if reason is None:
        logger.info(f"foreign exploit: {exploit.name} unchanged (sha256 {exploit_sha[:8]}); reusing repacked initramfs")
        return out
    logger.info(f"foreign exploit: rebuilding initramfs ({reason})")

    # Drop the Stamp BEFORE the work. An interrupted repack leaves a truncated but non-empty
    # output that passes the size check below; if the user then reverts the source edit, the
    # old Stamp would match again and hand back a corrupt initramfs.
    stamp.unlink(missing_ok=True)
    t0 = time.monotonic()
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
    stamp.write_text(json.dumps(inputs, sort_keys=True))
    logger.info(
        f"foreign exploit: repacked initramfs from {exploit.name} "
        f"(sha256 {exploit_sha[:8]}) in {time.monotonic() - t0:.1f}s"
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
            remedy="chunking corrupted the transfer: retry or use repack",
        )
