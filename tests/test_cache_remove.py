from types import SimpleNamespace

from likedbg.cache import Manifest
from likedbg.cache import manifest_exists
from likedbg.cache import manifest_path
from likedbg.cache import remove_cached
from likedbg.cache import remove_source
from likedbg.cache import write_manifest
from likedbg.container_service import ContainerService
from likedbg.errors import ContainerError


class FakeC(ContainerService):
    def __init__(self):
        self.execs: list[str] = []

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


class FakeCWithMissingPathError(ContainerService):
    """FakeC that raises ContainerError when unguarded chmod is called on a missing path."""

    def __init__(self, missing_path: str):
        self.execs: list[str] = []
        self.missing_path = missing_path

    def run_detached(self, image, **kwargs):
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        # If cmd is a bare chmod (not guarded by [ -d check), raise error
        if cmd.startswith("chmod") and self.missing_path in cmd:
            raise ContainerError(f"chmod failed: cannot access {self.missing_path}: No such file or directory")
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def test_remove_build_rms_volume_tree_and_host_export_and_manifest(tmp_path):
    label = "linux-6.6.30-aaaa"
    write_manifest(
        tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume")
    )
    export = tmp_path / "artifacts" / label
    export.mkdir(parents=True)
    (export / "Image").write_bytes(b"img")
    c = FakeC()
    remove_cached(
        c, tmp_path, Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="volume")
    )
    assert any(f"rm -rf /ksrc/obj/{label}" in e for e in c.execs)
    assert not export.exists()
    assert manifest_exists(tmp_path, "build", label) is False


def test_remove_rootfs_unlinks_image_and_manifest(tmp_path):
    label = "rootfs-arm64-bookworm-cccc"
    img = tmp_path / "artifacts" / "rootfs" / f"{label}.img"
    img.parent.mkdir(parents=True)
    img.write_bytes(b"img")
    write_manifest(
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(img)},
        ),
    )
    c = FakeC()
    remove_cached(
        c,
        tmp_path,
        Manifest(
            kind="rootfs",
            label=label,
            key="k",
            version="",
            arch="arm64",
            storage_mode="volume",
            paths={"image_host": str(img)},
        ),
    )
    assert c.execs == []  # rootfs lives on the host; no container needed
    assert not img.exists()
    assert manifest_exists(tmp_path, "rootfs", label) is False


def test_remove_bind_build_rmtrees_host_tree(tmp_path):
    label = "linux-6.6.30-bbbb"
    tree = tmp_path / "artifacts" / "ksrc" / "obj" / label / "arch" / "arm64" / "boot"
    tree.mkdir(parents=True)
    (tree / "Image").write_bytes(b"img")
    m = Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="bind")
    write_manifest(tmp_path, m)
    c = FakeC()
    remove_cached(c, tmp_path, m)
    assert c.execs == []  # bind tree is on the host; no container needed
    assert not (tmp_path / "artifacts" / "ksrc" / "obj" / label).exists()
    assert manifest_exists(tmp_path, "build", label) is False


def test_remove_source_volume_chmods_and_rms_and_unlinks_manifest(tmp_path):
    src_label = "linux-6.6.30-gef-deadbeef"
    write_manifest(
        tmp_path,
        Manifest(kind="source", label=src_label, key="k", version="6.6.30", arch="arm64", storage_mode="volume"),
    )
    c = FakeC()
    remove_source(c, tmp_path, src_label, storage_mode="volume")
    assert any("chmod -R u+w" in e and f"/ksrc/src/{src_label}" in e for e in c.execs)
    assert any(f"rm -rf /ksrc/src/{src_label}" in e for e in c.execs)
    assert manifest_exists(tmp_path, "source", src_label) is False


def test_remove_source_bind_chmods_writable_then_rmtrees_and_unlinks_manifest(tmp_path):
    src_label = "linux-6.6.30-gef-deadbeef"
    src_tree = tmp_path / "artifacts" / "ksrc" / "src" / src_label
    src_tree.mkdir(parents=True)
    (src_tree / "Makefile").write_bytes(b"x")
    src_tree.chmod(0o555)  # simulate the a-w source tree
    write_manifest(
        tmp_path,
        Manifest(kind="source", label=src_label, key="k", version="6.6.30", arch="arm64", storage_mode="bind"),
    )
    c = FakeC()
    try:
        remove_source(c, tmp_path, src_label, storage_mode="bind")
    finally:
        if src_tree.exists():
            src_tree.chmod(0o755)
    assert c.execs == []  # bind tree is on the host; no container needed
    assert not src_tree.exists()
    assert manifest_exists(tmp_path, "source", src_label) is False
    assert manifest_path(tmp_path, "source", src_label).exists() is False


def test_remove_source_volume_tolerates_missing_tree(tmp_path):
    src_label = "linux-6.6.30-missing-cccc"
    src_path = f"/ksrc/src/{src_label}"
    write_manifest(
        tmp_path,
        Manifest(kind="source", label=src_label, key="k", version="6.6.30", arch="arm64", storage_mode="volume"),
    )
    # Use FakeC that raises ContainerError on unguarded chmod of missing path
    c = FakeCWithMissingPathError(src_path)
    # Should not raise even though the source tree is missing
    remove_source(c, tmp_path, src_label, storage_mode="volume")
    # Verify the guarded command was executed (with [ -d ... ] check)
    assert any("[ -d" in e and "chmod" in e for e in c.execs)
    # Verify manifest is still unlinked
    assert manifest_exists(tmp_path, "source", src_label) is False
