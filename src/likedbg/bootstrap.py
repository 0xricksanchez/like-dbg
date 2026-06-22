"""Host prerequisite checks for the build/run environment (pure logic; installs
are done by scripts/bootstrap.sh). Each missing prerequisite carries a remedy."""

from __future__ import annotations

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
