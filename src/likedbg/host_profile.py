"""Host-capability detection. All side-effecting checks go through `Probes` so the
resolution logic is pure and unit-testable."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from likedbg.config import Arch
from likedbg.config import Settings
from likedbg.errors import HostCapabilityError

Accel = Literal["kvm", "hvf", "tcg"]
DebuggeeMode = Literal["in-container", "native-host"]
StorageMode = Literal["bind", "volume"]
NetworkMode = Literal["host", "published"]


def _real_system() -> str:
    return platform.system().lower()


def _real_machine() -> str:
    m = platform.machine().lower()
    return "arm64" if m in {"arm64", "aarch64"} else "x86_64"


def _real_kvm_accessible() -> bool:
    return Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK)


def _real_hvf_supported() -> bool:
    try:
        out = subprocess.run(["sysctl", "-n", "kern.hv_support"], capture_output=True, text=True, check=False)
    except OSError:
        return False
    return out.stdout.strip() == "1"


def _real_native_qemu_present(arch: Arch) -> bool:
    binary = "qemu-system-aarch64" if arch == "arm64" else "qemu-system-x86_64"
    return shutil.which(binary) is not None


def _real_case_sensitive(path: Path) -> bool:
    base = path if path.exists() else path.parent
    if not base.exists():
        base = Path(tempfile.gettempdir())
    probe = base / ".likedbg_CaseProbe"
    lower = base / ".likedbg_caseprobe"
    try:
        probe.write_text("x")
        return not lower.exists()
    except OSError:
        return True
    finally:
        probe.unlink(missing_ok=True)


@dataclass(frozen=True)
class Probes:
    system: Callable[[], str] = _real_system
    machine: Callable[[], str] = _real_machine
    kvm_accessible: Callable[[], bool] = _real_kvm_accessible
    hvf_supported: Callable[[], bool] = _real_hvf_supported
    native_qemu_present: Callable[[Arch], bool] = _real_native_qemu_present
    workspace_case_sensitive: Callable[[Path], bool] = _real_case_sensitive


@dataclass(frozen=True)
class HostProfile:
    os: str
    host_arch: str
    target_arch: Arch
    accel: Accel
    debuggee_mode: DebuggeeMode
    storage_mode: StorageMode
    gdbstub_addr: str
    network_mode: NetworkMode = "published"

    @classmethod
    def detect(cls, settings: Settings, workspace: Path, probes: Probes | None = None) -> HostProfile:
        if probes is None:
            probes = Probes()
        os_name = probes.system()
        host_arch = probes.machine()
        requested = settings.general.arch
        target_arch: Arch = host_arch if requested == "native" else requested  # type: ignore[assignment]
        same_arch = target_arch == host_arch

        capable_native_hvf = (
            os_name == "darwin" and same_arch and probes.hvf_supported() and probes.native_qemu_present(target_arch)
        )
        capable_kvm = os_name == "linux" and same_arch and probes.kvm_accessible()

        requested_accel = settings.debuggee.accel
        accel, mode = cls._resolve_accel(requested_accel, capable_native_hvf, capable_kvm, os_name)

        storage = cls._resolve_storage(settings, os_name, workspace, probes)
        network_mode = cls._resolve_network(settings.debuggee.network, os_name)
        # gdb is always containerized; it reaches QEMU on localhost (host networking, Linux)
        # or via the Docker gateway host.docker.internal (published port, macOS / native-host).
        addr = "localhost" if network_mode == "host" else "host.docker.internal"
        return cls(
            os=os_name,
            host_arch=host_arch,
            target_arch=target_arch,
            accel=accel,
            debuggee_mode=mode,
            storage_mode=storage,
            gdbstub_addr=addr,
            network_mode=network_mode,
        )

    @staticmethod
    def _resolve_accel(requested: str, native_hvf: bool, kvm: bool, os_name: str) -> tuple[Accel, DebuggeeMode]:
        if requested == "auto":
            # HVF requires macOS, KVM requires Linux: the two are mutually exclusive, so check order is irrelevant.
            if native_hvf:
                return "hvf", "native-host"
            if kvm:
                return "kvm", "in-container"
            return "tcg", "in-container"
        if requested == "hvf":
            if not native_hvf:
                raise HostCapabilityError(
                    "accel=hvf requested but HVF/native QEMU unavailable for this target",
                    remedy="use accel=auto, or run on an arm64 macOS host with qemu installed",
                )
            return "hvf", "native-host"
        if requested == "kvm":
            if not kvm:
                raise HostCapabilityError(
                    "accel=kvm requested but /dev/kvm is not accessible",
                    remedy="add your user to the 'kvm' group, or use accel=auto",
                )
            return "kvm", "in-container"
        return "tcg", "in-container"

    @staticmethod
    def _resolve_storage(settings: Settings, os_name: str, workspace: Path, probes: Probes) -> StorageMode:
        if os_name != "darwin":
            return "bind"
        override = settings.general.mac_storage
        if override == "bind":
            return "bind"
        if override == "volume":
            return "volume"
        return "bind" if probes.workspace_case_sensitive(workspace) else "volume"

    @staticmethod
    def _resolve_network(requested: str, os_name: str) -> NetworkMode:
        if requested == "host":
            if os_name == "darwin":
                raise HostCapabilityError(
                    "network=host is Linux-only (host networking on macOS targets the Docker VM, not the host)",
                    remedy="use network=auto or network=published on macOS",
                )
            return "host"
        if requested == "published":
            return "published"
        return "host" if os_name == "linux" else "published"  # auto
