"""Out-of-tree kernel module build + guest load/unload seam. The build runs `make -C <kernel_root>
M=/mod modules` in the kbuilder container (kernel tree RO at /ksrc, module source RW at /mod) with the
kernel's toolchain env so vermagic matches; loading rides 2a's guest.py (ssh insmod/rmmod). See ADR-0009."""

from __future__ import annotations

import shlex
import shutil
from pathlib import Path
from typing import Any

from likedbg import guest as _guest
from likedbg.constants import VOLUME_MOUNT
from likedbg.errors import ModuleError
from likedbg.input_hash import hash_tree

_MOD_MOUNT = "/mod"


def _make_cmd(kernel_root: str, env: dict[str, str]) -> str:
    vars_ = " ".join(f"{k}={v}" for k, v in env.items())
    return f"make -C {kernel_root} M={_MOD_MOUNT} {vars_} -j$(nproc) modules".replace("  ", " ")


def build_module(
    container: Any,
    *,
    src_dir: Path,
    kernel_root: str,
    mount_source: str,
    env: dict[str, str],
    out_dir: Path,
    image: str,
    volume: str,
) -> Path:
    """Build the out-of-tree module in `src_dir` against `kernel_root`; copy its `.ko` to `out_dir`."""
    c = container.run_detached(
        image,
        volumes={
            mount_source: {"bind": VOLUME_MOUNT, "mode": "ro"},
            str(src_dir): {"bind": _MOD_MOUNT, "mode": "rw"},
        },
        detach=True,
        tty=True,
    )
    try:
        container.exec(c, _make_cmd(kernel_root, env))
    finally:
        container.stop(c)
    kos = sorted(src_dir.glob("*.ko"))
    if not kos:
        raise ModuleError(
            f"module build produced no .ko in {src_dir}",
            remedy="check the module's obj-m Makefile and the build output",
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / kos[0].name
    shutil.copy2(kos[0], dest)
    return dest


def module_name(
    container: Any,
    ko: Path,
    *,
    image: str,
) -> str:
    """The loadable module name: `modinfo -F name`, else the .ko stem with `-`→`_`."""
    c = container.run_detached(
        image,
        volumes={str(ko.parent): {"bind": _MOD_MOUNT, "mode": "ro"}},
        detach=True,
        tty=True,
    )
    try:
        out = container.exec(c, f"modinfo -F name {_MOD_MOUNT}/{ko.name}").output
    finally:
        container.stop(c)
    name = out.replace("\r\n", "\n").strip()
    return name or ko.stem.replace("-", "_")


def _is_loaded(endpoint: object, name: str, client: Any) -> bool:
    r = client.run(endpoint, f"test -d /sys/module/{name} && echo Y || echo N")
    return bool(r.stdout.replace("\r\n", "\n").strip() == "Y")


def load(
    endpoint: object,
    ko: Path,
    *,
    name: str,
    share_dir: Path,
    share_mount: str,
    args: str = "",
    reload: bool = True,
    force_unload: bool = False,
    client: Any = _guest,
) -> Any:
    """Deliver `ko` to the guest and insmod it; reload = rmmod-then-insmod (EBUSY aborts unless force)."""
    try:
        remote = f"{share_mount}/{ko.resolve().relative_to(share_dir.resolve())}"
    except ValueError:
        remote = f"{share_mount}/modules/{ko.name}"
        client.push(endpoint, ko, remote)
    if reload and _is_loaded(endpoint, name, client):
        rm = client.run(endpoint, f"rmmod {'-f ' if force_unload else ''}{name}".strip())
        if rm.rc != 0:
            raise ModuleError(
                f"could not unload {name}: {rm.stderr.strip() or 'in use'}",
                remedy="close the module's users / restart the session, or pass --force-unload",
            )
    ins = client.run(endpoint, f"insmod {shlex.quote(remote)} {args}".strip())
    if ins.rc != 0:
        dmesg = client.run(endpoint, "dmesg | tail -n 20").stdout.replace("\r\n", "\n")
        raise ModuleError(
            f"insmod {name} failed (rc={ins.rc}): {ins.stderr.strip()}\n{dmesg}",
            remedy="vermagic mismatch → rebuild the kernel to match, or build the module from source",
        )
    return ins


def unload(endpoint: object, name: str, *, force: bool = False, client: Any = _guest) -> Any:
    return client.run(endpoint, f"rmmod {'-f ' if force else ''}{name}".strip())


def _stamp(src_dir: Path, kernel_label: str) -> str:
    return f"{kernel_label}:{hash_tree(src_dir).aggregate}"


def stale(src_dir: Path, ko: Path, kernel_label: str) -> bool:
    sidecar = ko.with_suffix(ko.suffix + ".hash")
    if not ko.is_file() or not sidecar.is_file():
        return True
    return sidecar.read_text().strip() != _stamp(src_dir, kernel_label)


def record_hash(src_dir: Path, ko: Path, kernel_label: str) -> None:
    ko.with_suffix(ko.suffix + ".hash").write_text(_stamp(src_dir, kernel_label))


def stage_module(
    container: Any,
    *,
    entry: Path,
    out_dir: Path,
    kernel_root: str,
    mount_source: str,
    env: dict[str, str],
    image: str,
    volume: str,
    kernel_label: str,
) -> Path:
    """Bring one custom_modules entry to a staged `.ko` in out_dir. Prebuilt `.ko` → copy it; source dir →
    build if the content hash (or kernel label) changed, else reuse the staged `.ko` (named after the dir)."""
    if entry.is_file() and entry.suffix == ".ko":
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / entry.name
        shutil.copy2(entry, dest)
        return dest
    ko = out_dir / f"{entry.name}.ko"
    if not stale(entry, ko, kernel_label):
        return ko
    built = build_module(
        container,
        src_dir=entry,
        kernel_root=kernel_root,
        mount_source=mount_source,
        env=env,
        out_dir=out_dir,
        image=image,
        volume=volume,
    )
    if built != ko:
        built.replace(ko)
    record_hash(entry, ko, kernel_label)
    return ko
