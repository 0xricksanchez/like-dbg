"""Shared, deterministic content hashing for workspace inputs (patch dirs today;
exploit payloads / custom modules later). One aggregate SHA-256 over sorted
(relative-path, file-hash) records, with a small documented junk ignore list."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_IGNORE_DIRS = frozenset({".git", "__pycache__", ".tmp_versions"})
_IGNORE_NAMES = frozenset({".DS_Store", "Module.symvers", "modules.order"})
_IGNORE_SUFFIXES = frozenset({".o", ".ko", ".mod", ".mod.c", ".cmd"})


@dataclass(frozen=True)
class IgnoreRules:
    dirs: frozenset[str] = _IGNORE_DIRS
    names: frozenset[str] = _IGNORE_NAMES
    suffixes: frozenset[str] = _IGNORE_SUFFIXES

    def skip_dir(self, name: str) -> bool:
        return name in self.dirs

    def skip_file(self, name: str) -> bool:
        return name in self.names or any(name.endswith(s) for s in self.suffixes)


DEFAULT_IGNORE = IgnoreRules()


@dataclass(frozen=True)
class TreeHash:
    aggregate: str
    files: tuple[tuple[str, str], ...]  # (relative POSIX path, sha256), sorted by path


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: Path, *, ignore: IgnoreRules = DEFAULT_IGNORE) -> TreeHash:
    records: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(ignore.skip_dir(part) for part in rel_parts[:-1]):
            continue
        if ignore.skip_file(path.name):
            continue
        rel = "/".join(rel_parts)
        records.append((rel, hash_file(path)))
    records.sort()
    agg = hashlib.sha256()
    for rel, digest in records:
        agg.update(rel.encode())
        agg.update(b"\0")
        agg.update(digest.encode())
        agg.update(b"\n")
    return TreeHash(aggregate=agg.hexdigest(), files=tuple(records))
