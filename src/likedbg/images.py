"""Container-image manifest + content-hash currency (ADR-0004; CONTEXT.md -> Container image).

Each Container image is checked for staleness by a content hash (`input_sha`) over its declared
build inputs — the dockerfile plus any local files it bakes in via COPY/ADD — stamped onto the
built image as the docker label `likedbg.input_sha`. `build_inputs` is declared explicitly per
image; a test (tests/test_images.py::test_build_inputs_cover_every_copy_source) enforces that the
declaration covers every COPY/ADD source, so it cannot silently drift.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGEE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import MUSL_IMAGE
from likedbg.constants import ROOTFS_IMAGE
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile

LABEL = "likedbg.input_sha"


@dataclass(frozen=True)
class ImageSpec:
    tag: str
    dockerfile: str
    build_inputs: tuple[str, ...]  # workspace-relative; build_inputs[0] is the dockerfile
    buildargs: dict[str, str]


# Dependency order: base first (the others are FROM like_dbg_base:latest).
IMAGES: tuple[ImageSpec, ...] = (
    ImageSpec(BASE_IMAGE, ".dockerfile_base", (".dockerfile_base",), {"USER": "user"}),
    ImageSpec(
        MUSL_IMAGE,
        ".dockerfile_musl",
        (".dockerfile_musl", "io/scripts/extract-vmlinux.sh"),
        {"USER": "user"},
    ),
    ImageSpec(KBUILDER_IMAGE, ".dockerfile_kbuilder", (".dockerfile_kbuilder",), {"USER": "user"}),
    ImageSpec(ROOTFS_IMAGE, ".dockerfile_rootfs", (".dockerfile_rootfs", "io/scripts/rootfs.sh"), {"USER": "user"}),
    ImageSpec(DEBUGGER_IMAGE, ".dockerfile_dbg", (".dockerfile_dbg",), {"USER": "user"}),
    ImageSpec(DEBUGGEE_IMAGE, ".dockerfile_dbge", (".dockerfile_dbge",), {"USER": "user"}),
)

# `--use` reuses a cached build, but may still re-export the volume Image (base), build the active
# rootfs when it is absent (rootfs), launch gdb (debugger), and launch QEMU in-container (debuggee).
USE_IMAGES: tuple[ImageSpec, ...] = tuple(
    s for s in IMAGES if s.tag in (BASE_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE, DEBUGGEE_IMAGE)
)


def input_sha(spec: ImageSpec, workspace: Path) -> str:
    """sha256 over the sorted (relpath, content) of the spec's build inputs."""
    h = hashlib.sha256()
    for rel in sorted(spec.build_inputs):
        h.update(rel.encode())
        h.update(b"\0")
        h.update((workspace / rel).read_bytes())
        h.update(b"\0")
    return h.hexdigest()


_COPY_RE = re.compile(r"^\s*(?:COPY|ADD)\s+(.*)$")
_GLOB_CHARS = set("*?[")


def copy_sources(dockerfile_text: str) -> list[str]:
    """Local source paths a dockerfile bakes in via COPY/ADD (for the build_inputs completeness test).

    Strict: raises ValueError on patterns we cannot statically resolve (globs, directory copies, the
    JSON-array form) so a future dockerfile change forces a conscious build_inputs update (ADR-0004).
    Skips URL sources and `--from=` multi-stage copies (not local build inputs).
    """
    out: list[str] = []
    for line in dockerfile_text.splitlines():
        m = _COPY_RE.match(line)
        if not m:
            continue
        rest = m.group(1).strip()
        if rest.startswith("["):
            raise ValueError(f"unhandled JSON-array COPY/ADD form: {line!r}")
        raw_tokens = rest.split()
        if any(t == "--from" or t.startswith("--from=") for t in raw_tokens if t.startswith("--")):
            continue  # multi-stage copy: sources live in another build stage, not the workspace
        tokens = [t for t in raw_tokens if not t.startswith("--")]  # drop flags (e.g. --chown=)
        if len(tokens) < 2:
            raise ValueError(f"unparseable COPY/ADD (need source + dest): {line!r}")
        for src in tokens[:-1]:  # last token is the destination
            if src.startswith(("http://", "https://")):
                continue
            if src.endswith("/") or any(c in _GLOB_CHARS for c in src):
                raise ValueError(f"unhandled glob/dir COPY/ADD source {src!r} in: {line!r}")
            out.append(src)
    return out


def build_images(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> None:
    """(Re)build every spec in dependency order, stamping the input_sha label."""
    for s in specs:
        logger.info(f"building image {s.tag} from {s.dockerfile}")
        container.build_image(s.dockerfile, s.tag, s.buildargs, labels={LABEL: input_sha(s, workspace)})


def ensure_current(container: ContainerService, workspace: Path, specs: tuple[ImageSpec, ...] = IMAGES) -> list[str]:
    """Auto-build MISSING images (in order); return the tags of present-but-STALE images.

    Stale = the live image's `likedbg.input_sha` label != the freshly computed input_sha. The caller
    warns about stale tags; ensure_current never rebuilds them (warn-only, ADR-0004).
    """
    stale: list[str] = []
    for s in specs:
        want = input_sha(s, workspace)
        if not container.image_exists(s.tag):
            logger.info(f"building missing image {s.tag} from {s.dockerfile}")
            container.build_image(s.dockerfile, s.tag, s.buildargs, labels={LABEL: want})
        elif container.image_labels(s.tag).get(LABEL) != want:
            stale.append(s.tag)
    return stale


def required_for(host: HostProfile) -> tuple[ImageSpec, ...]:
    """Images a build+boot+debug run needs: the four base images always, plus the debuggee image
    only for in-container runs (a native-host run launches QEMU on the host and never uses it).

    Explicit tag set (rather than "IMAGES minus debuggee") because IMAGES also carries images for
    other flows (e.g. MUSL_IMAGE, used only by the foreign/CTF-adopt flow via required_for_foreign)
    that a normal build+boot+debug run does not need.
    """
    tags = {BASE_IMAGE, KBUILDER_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE}
    if host.debuggee_mode == "in-container":
        tags.add(DEBUGGEE_IMAGE)
    return tuple(s for s in IMAGES if s.tag in tags)


def required_for_use(host: HostProfile) -> tuple[ImageSpec, ...]:
    """Images a cached-build `--use` run needs, with debuggee only for in-container QEMU."""
    if host.debuggee_mode == "in-container":
        return USE_IMAGES
    return tuple(s for s in USE_IMAGES if s.tag != DEBUGGEE_IMAGE)


def foreign_prep_images() -> tuple[ImageSpec, ...]:
    """base + musl — needed before host/arch detection (extract vmlinux, repack)."""
    return tuple(s for s in IMAGES if s.tag in (BASE_IMAGE, MUSL_IMAGE))


def required_for_foreign(host: HostProfile) -> tuple[ImageSpec, ...]:
    """Images a foreign (CTF-adopt) run needs; debuggee only for in-container QEMU."""
    tags = {BASE_IMAGE, MUSL_IMAGE, DEBUGGER_IMAGE}
    if host.debuggee_mode == "in-container":
        tags.add(DEBUGGEE_IMAGE)
    return tuple(s for s in IMAGES if s.tag in tags)
