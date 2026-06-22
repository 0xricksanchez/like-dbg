"""Host prerequisite checks for the build/run environment (pure logic; installs
are done by scripts/bootstrap.sh). Each missing prerequisite carries a remedy."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Prereq:
    name: str
    ok: bool
    remedy: str | None


@dataclass(frozen=True)
class BootstrapProbes:
    has: Callable[[str], bool]
    colima_running: Callable[[], bool]
    binfmt_arm64: Callable[[], bool]


def check_prerequisites(os_name: str, probes: BootstrapProbes) -> list[Prereq]:
    results: list[Prereq] = []
    results.append(
        Prereq("uv", probes.has("uv"), None if probes.has("uv") else "install uv: https://docs.astral.sh/uv/")
    )
    if os_name == "darwin":
        colima_ok = probes.has("colima") and probes.colima_running()
        results.append(
            Prereq(
                "colima",
                colima_ok,
                None
                if colima_ok
                else ("brew install colima && colima start" if not probes.has("colima") else "colima start"),
            )
        )
        results.append(
            Prereq(
                "qemu-system-aarch64",
                probes.has("qemu-system-aarch64"),
                None if probes.has("qemu-system-aarch64") else "brew install qemu",
            )
        )
    else:
        results.append(
            Prereq("docker", probes.has("docker"), None if probes.has("docker") else "install Docker engine")
        )
    results.append(
        Prereq(
            "binfmt-arm64",
            probes.binfmt_arm64(),
            None if probes.binfmt_arm64() else "docker run --privileged --rm tonistiigi/binfmt --install all",
        )
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

    def binfmt_arm64() -> bool:
        return shutil.which("docker") is not None  # refined in Task 8 bring-up

    return BootstrapProbes(
        has=lambda cmd: shutil.which(cmd) is not None,
        colima_running=colima_running,
        binfmt_arm64=binfmt_arm64,
    )


def main(argv: list[str] | None = None) -> int:
    import platform

    args = sys.argv[1:] if argv is None else argv
    if args and args[0] not in ("--check",):
        print("usage: python -m likedbg.bootstrap [--check]", file=sys.stderr)
        return 2
    results = check_prerequisites(platform.system().lower(), _real_probes())
    failed = [r for r in results if not r.ok]
    for r in results:
        mark = "ok" if r.ok else "MISSING"
        line = f"[{mark}] {r.name}"
        if r.remedy:
            line += f"  -> {r.remedy}"
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
