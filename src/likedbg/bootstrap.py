"""Host prerequisite checks for the build/run environment (pure logic; installs
are done by scripts/bootstrap.sh). Each missing prerequisite carries a remedy."""

from __future__ import annotations

import platform
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# "unknown" is a real answer, not a hedge: the binfmt handler lives in the kernel that runs the
# containers, and on macOS that is inside the Docker VM, which the host cannot inspect. Reporting
# a pass there would be a guess, and a guess in a prerequisite check is worse than no check.
PrereqStatus = Literal["ok", "missing", "unknown"]

_BINFMT_DIR = Path("/proc/sys/fs/binfmt_misc")
_BINFMT_REMEDY = "docker run --privileged --rm tonistiigi/binfmt --install all"
_ARM64_MACHINES = frozenset({"arm64", "aarch64"})


@dataclass(frozen=True)
class Prereq:
    name: str
    status: PrereqStatus
    remedy: str | None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True)
class BootstrapProbes:
    has: Callable[[str], bool]
    colima_running: Callable[[], bool]
    binfmt_registered: Callable[[str], bool]  # qemu handler name -> registered in this kernel


def _foreign_qemu_arch(machine: str) -> str:
    """The QEMU arch a rootfs build would have to emulate on this host -- i.e. the one it does
    NOT run natively. io/scripts/rootfs.sh only takes its binfmt path when ARCH != `uname -m`."""
    return "x86_64" if machine in _ARM64_MACHINES else "aarch64"


def check_prerequisites(os_name: str, probes: BootstrapProbes, *, machine: str = "x86_64") -> list[Prereq]:
    results: list[Prereq] = []
    results.append(
        Prereq(
            "uv",
            "ok" if probes.has("uv") else "missing",
            None if probes.has("uv") else "install uv: https://docs.astral.sh/uv/",
        )
    )
    if os_name == "darwin":
        colima_ok = probes.has("colima") and probes.colima_running()
        results.append(
            Prereq(
                "colima",
                "ok" if colima_ok else "missing",
                None
                if colima_ok
                else ("brew install colima && colima start" if not probes.has("colima") else "colima start"),
            )
        )
        qemu_ok = probes.has("qemu-system-aarch64")
        results.append(
            Prereq("qemu-system-aarch64", "ok" if qemu_ok else "missing", None if qemu_ok else "brew install qemu")
        )
    else:
        docker_ok = probes.has("docker")
        results.append(
            Prereq("docker", "ok" if docker_ok else "missing", None if docker_ok else "install Docker engine")
        )

    qemu_arch = _foreign_qemu_arch(machine)
    if os_name == "darwin":
        results.append(
            Prereq(
                f"binfmt-{qemu_arch}",
                "unknown",
                f"not visible from the host (it lives in the Docker VM); if a foreign-arch "
                f"rootfs build fails, run: {_BINFMT_REMEDY}",
            )
        )
    else:
        binfmt_ok = probes.binfmt_registered(f"qemu-{qemu_arch}")
        results.append(
            Prereq(f"binfmt-{qemu_arch}", "ok" if binfmt_ok else "missing", None if binfmt_ok else _BINFMT_REMEDY)
        )
    return results


def _real_probes() -> BootstrapProbes:
    import shutil
    import subprocess

    def colima_running() -> bool:
        if shutil.which("colima") is None:
            return False
        out = subprocess.run(["colima", "status"], capture_output=True, text=True, check=False)
        return "running" in (out.stdout + out.stderr).lower()

    def binfmt_registered(handler: str) -> bool:
        # Same registry io/scripts/rootfs.sh reads before a foreign-arch debootstrap. binfmt_misc
        # is kernel-global, so on Linux the host's view is the containers' view.
        return (_BINFMT_DIR / handler).is_file()

    return BootstrapProbes(
        has=lambda cmd: shutil.which(cmd) is not None,
        colima_running=colima_running,
        binfmt_registered=binfmt_registered,
    )


_MARKS: dict[PrereqStatus, str] = {"ok": "ok", "missing": "MISSING", "unknown": "note"}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] not in ("--check",):
        print("usage: python -m likedbg.bootstrap [--check]", file=sys.stderr)
        return 2
    results = check_prerequisites(platform.system().lower(), _real_probes(), machine=platform.machine())
    for r in results:
        line = f"[{_MARKS[r.status]}] {r.name}"
        if r.remedy:
            line += f"  -> {r.remedy}"
        print(line)
    # Only a definite "missing" fails the check; an unverifiable one must not block a green run.
    return 1 if any(r.status == "missing" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
