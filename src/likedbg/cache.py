"""Content-addressed Build Cache: Recipe value objects (single source of truth for what a
Kernel Build / rootfs is), key + Label derivation, the host-side Manifest registry, and
storage-mode-aware location resolution.

A Kernel Build is identified by its requested configuration, not by toolchain/image
identity (ADR-0003).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from likedbg.config import Arch
from likedbg.config import Settings
from likedbg.constants import BASE_IMAGE
from likedbg.constants import KERNEL_VOLUME
from likedbg.constants import VOLUME_MOUNT
from likedbg.container_service import ContainerService
from likedbg.errors import CacheError
from likedbg.input_hash import hash_tree
from likedbg.toolchain import resolve_toolchain

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_NOT_SET_RE = re.compile(r"^# CONFIG_\w+ is not set$")
_ROOTFS_SCRIPT = "io/scripts/rootfs.sh"

TREE_ROOT = "ksrc"  # host mirror of the kernel-source mount: artifacts/<TREE_ROOT>/<label>

_SIZE_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


def parse_size(s: str) -> int:
    """Parse a ccache-style size string ('50G', '500M', '') to bytes. '' -> 0 (no cap)."""
    s = s.strip().upper()
    if not s:
        return 0
    unit = s[-1] if s[-1] in "KMGT" else ""
    num = s[:-1] if unit else s
    try:
        return int(float(num) * _SIZE_UNITS[unit])
    except (ValueError, KeyError) as exc:
        raise ValueError(f"invalid size {s!r}: use e.g. 50G, 500M") from exc


def parse_du_bytes(out: str) -> int:
    """Parse `du -sb` output tolerantly; returns 0 on malformed/empty input.

    `du -sb <path>` normally returns "<size_bytes>\t<path>\n"; we extract the size.
    On empty output or parse failure, returns 0 instead of raising (best-effort accounting).
    """
    try:
        return int(out.split()[0])
    except (IndexError, ValueError):
        return 0


def cache_key(inputs: dict[str, str]) -> str:
    blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def normalize_fragment(text: str) -> str:
    """Canonicalize a kconfig fragment for cache keying: drop blank lines, trailing whitespace,
    and comment lines, but keep every directive including `# CONFIG_X is not set` (a real kconfig
    line, not a comment). Order is preserved, so doc-only edits no longer change the build key."""
    kept: list[str] = []
    for line in text.splitlines():
        s = line.rstrip()
        if not s:
            continue
        if s.startswith("#") and not _NOT_SET_RE.match(s):
            continue
        kept.append(s)
    return "\n".join(kept)


def short_hash(key: str) -> str:
    return key[:8]


def slug(text: str) -> str:
    """Kebab-slug for Labels: lowercase, collapse runs of non-[a-z0-9._-] to '-', trim '-'."""
    return _SLUG_RE.sub("-", text.lower()).strip("-")


@dataclass(frozen=True)
class BuildRecipe:
    version: str
    arch: str
    compiler: str
    make_vars: tuple[tuple[str, str], ...]
    frag_hashes: tuple[tuple[str, str], ...]
    fragments: tuple[str, ...]
    patch_hashes: tuple[tuple[str, str], ...] = ()
    kernel_tag: str = ""

    def env(self) -> dict[str, str]:
        return dict(self.make_vars)

    def cache_inputs(self) -> dict[str, str]:
        inputs = {
            "version": self.version,
            "arch": self.arch,
            "compiler": self.compiler,
            "kernel_tag": self.kernel_tag,
        }
        inputs.update({f"frag:{name}": h for name, h in self.frag_hashes})
        inputs.update({f"patch:{name}": h for name, h in self.patch_hashes})
        return inputs

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        tag = f"-{slug(self.kernel_tag)}" if self.kernel_tag else ""
        return f"linux-{slug(self.version)}{tag}-{short_hash(self.key)}"

    @property
    def src_key(self) -> str:
        inputs = {"version": self.version, "kernel_tag": self.kernel_tag}
        inputs.update({f"patch:{name}": h for name, h in self.patch_hashes})
        return cache_key(inputs)

    @property
    def src_label(self) -> str:
        tag = f"-{slug(self.kernel_tag)}" if self.kernel_tag else ""
        return f"linux-{slug(self.version)}{tag}-{short_hash(self.src_key)}"


@dataclass(frozen=True)
class RootfsRecipe:
    arch: str
    distribution: str
    hostname: str
    script_sha: str = ""

    def cache_inputs(self) -> dict[str, str]:
        inputs = {"arch": self.arch, "distribution": self.distribution, "hostname": self.hostname}
        if self.script_sha:
            inputs[f"script:{_ROOTFS_SCRIPT}"] = self.script_sha
        return inputs

    @property
    def key(self) -> str:
        return cache_key(self.cache_inputs())

    @property
    def label(self) -> str:
        return f"rootfs-{slug(self.arch)}-{slug(self.distribution)}-{short_hash(self.key)}"


def build_recipe(
    settings: Settings,
    *,
    version: str,
    arch: Arch,
    workspace: Path,
    fragments: list[str],
    patch_dirs: tuple[str, ...] = (),
) -> BuildRecipe:
    tc = resolve_toolchain(settings.build.compiler, arch)
    frag_hashes = sorted(
        (rel, hashlib.sha256(normalize_fragment((workspace / rel).read_text(encoding="utf-8")).encode()).hexdigest())
        for rel in fragments
    )
    patch_hashes = tuple((rel, hash_tree(workspace / rel).aggregate) for rel in patch_dirs)
    return BuildRecipe(
        version=version,
        arch=arch,
        compiler=settings.build.compiler,
        make_vars=tuple(sorted(tc.make_vars.items())),
        frag_hashes=tuple(frag_hashes),
        fragments=tuple(fragments),
        patch_hashes=patch_hashes,
        kernel_tag=settings.build.label_suffix,
    )


def rootfs_recipe(settings: Settings, *, arch: Arch | None = None, workspace: Path | None = None) -> RootfsRecipe:
    script = workspace / _ROOTFS_SCRIPT if workspace is not None else None
    script_sha = hashlib.sha256(script.read_bytes()).hexdigest() if script is not None and script.exists() else ""
    return RootfsRecipe(
        arch=arch or settings.general.arch,
        distribution=settings.rootfs.distribution,
        hostname=settings.rootfs.hostname,
        script_sha=script_sha,
    )


@dataclass(frozen=True)
class Manifest:
    kind: str
    label: str
    key: str
    version: str
    arch: str
    srckey: str = ""
    kernel_release: str = ""
    storage_mode: str = ""
    inputs: dict[str, str] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    last_used: str = ""
    size_bytes: int = 0


# Registry sub-directory per artifact kind (spec section 4.3). NOT f"{kind}s": that would
# pluralize "rootfs" to the wrong "rootfss".
_KIND_DIR = {"build": "builds", "rootfs": "rootfs", "source": "sources"}


def manifest_path(workspace: Path, kind: str, label: str) -> Path:
    return workspace / "artifacts" / "cache" / _KIND_DIR[kind] / f"{label}.json"


def manifest_exists(workspace: Path, kind: str, label: str) -> bool:
    return manifest_path(workspace, kind, label).exists()


def write_manifest(workspace: Path, manifest: Manifest) -> Path:
    path = manifest_path(workspace, manifest.kind, manifest.label)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, suffix=".json.tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(manifest.__dict__, indent=2, sort_keys=True))
        tmp.replace(path)  # atomic on the same filesystem
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path


def load_manifest(workspace: Path, kind: str, label: str) -> Manifest:
    path = manifest_path(workspace, kind, label)
    if not path.exists():
        raise CacheError(f"no cached {kind} labelled {label!r}", remedy="run `start_kgdb --list`")
    try:
        data = json.loads(path.read_text())
        return Manifest(**data)
    except (ValueError, TypeError) as exc:
        raise CacheError(f"corrupt manifest {path}", remedy=f"`start_kgdb --clean {label}` and rebuild") from exc


def list_manifests(workspace: Path, kind: str) -> list[Manifest]:
    registry = workspace / "artifacts" / "cache" / _KIND_DIR[kind]
    if not registry.is_dir():
        return []
    return [load_manifest(workspace, kind, p.stem) for p in sorted(registry.glob("*.json"), key=lambda p: p.stem)]


def source_refcount(workspace: Path, srckey: str) -> int:
    """Number of build manifests currently referencing the source keyed `srckey`. A source is
    orphaned (safe to remove) once this drops to zero."""
    return sum(1 for b in list_manifests(workspace, "build") if b.srckey == srckey)


@dataclass(frozen=True)
class Locations:
    vmlinux_in_tree: str
    image_in_tree: str
    image_host: str
    gdb_mount_source: str
    gdb_mount_type: str
    gdb_vmlinux: str
    source_root: str = ""
    objdir: str = ""


def tree_mount_source(workspace: Path, *, storage_mode: str, volume: str = KERNEL_VOLUME) -> str:
    """The kernel tree's mount source: the named volume (volume mode) or the host
    artifacts/ksrc dir (bind mode). Mounted at VOLUME_MOUNT rw by Build/Unpack, ro by gdb."""
    return volume if storage_mode == "volume" else str(workspace / "artifacts" / TREE_ROOT)


def locations(
    label: str,
    *,
    arch: str,
    storage_mode: str,
    workspace: Path,
    volume: str = KERNEL_VOLUME,
    src_label: str | None = None,
) -> Locations:
    image_name = "bzImage" if arch == "x86_64" else "Image"
    objdir = f"{VOLUME_MOUNT}/obj/{label}"
    source_root = f"{VOLUME_MOUNT}/src/{src_label}" if src_label is not None else ""
    image_in_tree = f"{objdir}/arch/{arch}/boot/{image_name}"
    if storage_mode == "volume":
        return Locations(
            vmlinux_in_tree=f"{objdir}/vmlinux",
            image_in_tree=image_in_tree,
            image_host=str(workspace / "artifacts" / label / image_name.replace("bzImage", "Image")),
            gdb_mount_source=tree_mount_source(workspace, storage_mode=storage_mode, volume=volume),
            gdb_mount_type="volume",
            gdb_vmlinux=f"{objdir}/vmlinux",
            source_root=source_root,
            objdir=objdir,
        )
    host_objdir = workspace / "artifacts" / TREE_ROOT / "obj" / label  # the real on-host build dir (bind)
    return Locations(
        vmlinux_in_tree=f"{objdir}/vmlinux",
        image_in_tree=image_in_tree,  # container path (symmetric)
        image_host=str(host_objdir / "arch" / arch / "boot" / image_name),  # real host in-tree file
        gdb_mount_source=tree_mount_source(workspace, storage_mode=storage_mode, volume=volume),
        gdb_mount_type="bind",
        gdb_vmlinux=f"{objdir}/vmlinux",  # VOLUME_MOUNT/obj/<label>/vmlinux (symmetric)
        source_root=source_root,
        objdir=objdir,
    )


def remove_cached(
    container: ContainerService, workspace: Path, manifest: Manifest, *, volume: str = KERNEL_VOLUME
) -> None:
    if manifest.kind == "build":
        if manifest.storage_mode == "volume":
            c = container.run_detached(
                BASE_IMAGE, volumes={volume: {"bind": VOLUME_MOUNT, "mode": "rw"}}, detach=True, tty=True
            )
            try:
                container.exec(c, f"rm -rf {VOLUME_MOUNT}/obj/{manifest.label}")
            finally:
                container.stop(c)
            export_dir = workspace / "artifacts" / manifest.label
            if export_dir.is_dir():
                shutil.rmtree(export_dir)
        else:  # bind: the objdir IS on the host, chown'd to the user at build time, so rmtree just works
            objdir = workspace / "artifacts" / TREE_ROOT / "obj" / manifest.label
            if objdir.is_dir():
                shutil.rmtree(objdir)
    else:
        image = Path(manifest.paths.get("image_host", ""))
        if image.is_file():
            image.unlink()
    manifest_path(workspace, manifest.kind, manifest.label).unlink(missing_ok=True)


def remove_source(
    container: ContainerService, workspace: Path, src_label: str, *, storage_mode: str, volume: str = KERNEL_VOLUME
) -> None:
    """Remove a cached source tree. The tree is made read-only (`chmod -R a-w`) after unpack, so it
    must be made writable again before it can be removed."""
    src_path = f"{VOLUME_MOUNT}/src/{src_label}"
    if storage_mode == "volume":
        c = container.run_detached(
            BASE_IMAGE, volumes={volume: {"bind": VOLUME_MOUNT, "mode": "rw"}}, detach=True, tty=True
        )
        try:
            container.exec(c, f"[ -d {src_path} ] && chmod -R u+w {src_path}; rm -rf {src_path}")
        finally:
            container.stop(c)
    else:  # bind: the tree is on the host, but read-only, so make it writable before rmtree
        tree = workspace / "artifacts" / TREE_ROOT / "src" / src_label
        if tree.is_dir():
            for root, dirs, files in os.walk(tree):
                for name in dirs:
                    (Path(root) / name).chmod(0o755)
                for name in files:
                    path = Path(root) / name
                    path.chmod(path.stat().st_mode | 0o200)
            tree.chmod(0o755)
            shutil.rmtree(tree)
    manifest_path(workspace, "source", src_label).unlink(missing_ok=True)
