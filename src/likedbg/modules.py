"""Out-of-tree kernel module build + guest load/unload seam. The build runs `make -C <kernel_root>
M=/mod modules` in the kbuilder container (kernel tree RO at /ksrc, module source RW at /mod) with the
kernel's toolchain env so vermagic matches; loading rides 2a's guest.py (ssh insmod/rmmod). See ADR-0009."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from likedbg.constants import VOLUME_MOUNT
from likedbg.errors import ModuleError

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
