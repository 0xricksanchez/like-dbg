"""Content-addressed Build Cache: Recipe value objects (single source of truth for what a
Kernel Build / rootfs is), key + Label derivation, the host-side Manifest registry, and
storage-mode-aware location resolution.

See docs/superpowers/specs/2026-06-23-build-reuse-cache-design.md and ADR-0003: a Kernel
Build is identified by its requested configuration, not by toolchain/image identity.
"""

from __future__ import annotations

import hashlib
import json
import re

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def cache_key(inputs: dict[str, str]) -> str:
    blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def short_hash(key: str) -> str:
    return key[:8]


def slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")
