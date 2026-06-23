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

from likedbg.constants import BASE_IMAGE
from likedbg.constants import DEBUGGER_IMAGE
from likedbg.constants import KBUILDER_IMAGE
from likedbg.constants import ROOTFS_IMAGE

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
    ImageSpec(KBUILDER_IMAGE, ".dockerfile_kbuilder", (".dockerfile_kbuilder",), {"USER": "user"}),
    ImageSpec(ROOTFS_IMAGE, ".dockerfile_rootfs", (".dockerfile_rootfs", "io/scripts/rootfs.sh"), {"USER": "user"}),
    ImageSpec(DEBUGGER_IMAGE, ".dockerfile_dbg", (".dockerfile_dbg",), {"USER": "user"}),
)
# NOTE: the debuggee image (.dockerfile_dbge, FROM base) joins this manifest in B2 (x86_64-on-Mac),
# its first consumer; intentionally absent now (unbuilt + unvalidated today).

# `--use` is launch-only (boots a cached build): it needs gdb's debugger image, and base only for
# the rare re-export when the host Image was deleted. It never builds a kernel or rootfs.
USE_IMAGES: tuple[ImageSpec, ...] = tuple(s for s in IMAGES if s.tag in (BASE_IMAGE, DEBUGGER_IMAGE))


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
        if "--from" in rest:
            continue  # multi-stage copy: sources live in another build stage, not the workspace
        if rest.startswith("["):
            raise ValueError(f"unhandled JSON-array COPY/ADD form: {line!r}")
        tokens = [t for t in rest.split() if not t.startswith("--")]  # drop flags (e.g. --chown=)
        if len(tokens) < 2:
            raise ValueError(f"unparseable COPY/ADD (need source + dest): {line!r}")
        for src in tokens[:-1]:  # last token is the destination
            if src.startswith(("http://", "https://")):
                continue
            if src.endswith("/") or any(c in _GLOB_CHARS for c in src):
                raise ValueError(f"unhandled glob/dir COPY/ADD source {src!r} in: {line!r}")
            out.append(src)
    return out
