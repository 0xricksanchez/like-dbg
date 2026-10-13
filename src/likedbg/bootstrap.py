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
    docker_ready: Callable[[], bool]  # a daemon actually answers, whichever engine provides it
    binfmt_registered: Callable[[str], bool]  # qemu handler name -> registered in this kernel


def _foreign_qemu_arch(machine: str) -> str:
    """The QEMU arch a rootfs build would have to emulate on this host -- i.e. the one it does
    NOT run natively. io/scripts/rootfs.sh only takes its binfmt path when ARCH != `uname -m`."""
    return "x86_64" if machine in _ARM64_MACHINES else "aarch64"


def _docker_prereq(os_name: str, probes: BootstrapProbes) -> Prereq:
    if not probes.has("docker"):
        remedy = (
            "install a Docker engine (Docker Desktop, colima, or OrbStack)"
            if os_name == "darwin"
            else "install the Docker engine"
        )
        return Prereq("docker", "missing", remedy)
    if not probes.docker_ready():
        remedy = "start it (e.g. `colima start`, or launch Docker Desktop)" if os_name == "darwin" else "start dockerd"
        return Prereq("docker", "missing", f"the docker CLI is installed but no daemon answers -- {remedy}")
    return Prereq("docker", "ok", None)


def check_prerequisites(os_name: str, probes: BootstrapProbes, *, machine: str = "x86_64") -> list[Prereq]:
    results: list[Prereq] = []
    results.append(
        Prereq(
            "uv",
            "ok" if probes.has("uv") else "missing",
            None if probes.has("uv") else "install uv: https://docs.astral.sh/uv/",
        )
    )
    # LIKE-DBG talks to whatever the active Docker CLI context points at (docker_env.resolve_docker_host),
    # so the question is never "is colima installed" -- it is "does a daemon answer". Docker Desktop,
    # colima, OrbStack and a remote context are all equally fine.
    results.append(_docker_prereq(os_name, probes))
    if os_name == "darwin":
        # QEMU runs as a host process here for a same-arch guest, so it must be installed.
        qemu_ok = probes.has("qemu-system-aarch64")
        results.append(
            Prereq("qemu-system-aarch64", "ok" if qemu_ok else "missing", None if qemu_ok else "brew install qemu")
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

    def docker_ready() -> bool:
        """Whether a daemon answers on the active context -- engine-agnostic, exactly like the
        client LIKE-DBG builds at runtime."""
        if shutil.which("docker") is None:
            return False
        return subprocess.run(["docker", "info"], capture_output=True, text=True, check=False).returncode == 0

    def binfmt_registered(handler: str) -> bool:
        # Same registry io/scripts/rootfs.sh reads before a foreign-arch debootstrap. binfmt_misc
        # is kernel-global, so on Linux the host's view is the containers' view.
        return (_BINFMT_DIR / handler).is_file()

    return BootstrapProbes(
        has=lambda cmd: shutil.which(cmd) is not None,
        docker_ready=docker_ready,
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
