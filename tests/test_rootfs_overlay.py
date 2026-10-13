from pathlib import Path
from types import SimpleNamespace

import pytest

from likedbg.errors import RootfsError
from likedbg.rootfs_overlay import ensure_overlay
from likedbg.rootfs_overlay import overlay_path
from likedbg.rootfs_overlay import overlays_for


class _FakeQemuImg:
    """Stands in for qemu-img in the debuggee container, recording how it was invoked."""

    def __init__(self, *, create: bool = True) -> None:
        self.execs: list[str] = []
        self.volumes: dict | None = None
        self._create = create

    def run_detached(self, image, **kwargs):
        self.volumes = kwargs.get("volumes")
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if self._create:
            # mirror `cd <dir> && qemu-img create ... <name>`
            parts = cmd.split()
            target = parts[-1].strip("'")
            base_dir = Path(parts[1].strip("'"))
            (base_dir / target).write_bytes(b"QFI\xfb")
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _base(tmp_path: Path) -> Path:
    d = tmp_path / "artifacts" / "rootfs"
    d.mkdir(parents=True)
    img = d / "rootfs-x86_64-bookworm-abc123.img"
    img.write_bytes(b"raw-disk")
    return img


def test_overlay_lives_beside_its_base_and_is_named_for_the_session(tmp_path: Path) -> None:
    base = _base(tmp_path)
    got = overlay_path(base, "LIKE-DBG-lk01")
    assert got.parent == base.parent
    assert got.name == "rootfs-x86_64-bookworm-abc123.img.LIKE-DBG-lk01.qcow2"


def test_creating_an_overlay_uses_a_relative_backing_name(tmp_path: Path) -> None:
    """The overlay is opened by QEMU on the host (macOS) or inside the debuggee container
    (Linux), where the mount layout differs. A relative backing name resolves in both."""
    base = _base(tmp_path)
    c = _FakeQemuImg()
    ensure_overlay(c, base=base, session_name="LIKE-DBG-lk01", image="like_debuggee:latest")

    cmd = c.execs[0]
    create = cmd.split("&&")[1]
    assert "qemu-img create -f qcow2" in create
    assert f"-b {base.name} " in create  # the bare name...
    assert str(base.parent) not in create  # ...never an absolute path baked into the overlay
    assert c.volumes == {str(base.parent): {"bind": str(base.parent), "mode": "rw"}}


def test_an_existing_overlay_is_reused_so_a_re_run_keeps_guest_state(tmp_path: Path) -> None:
    base = _base(tmp_path)
    c = _FakeQemuImg()
    first = ensure_overlay(c, base=base, session_name="s", image="i")
    second = ensure_overlay(c, base=base, session_name="s", image="i")
    assert first == second
    assert len(c.execs) == 1  # the second boot created nothing


def test_each_session_gets_its_own_overlay(tmp_path: Path) -> None:
    """The whole point: two concurrent guests must not share one write-locked image."""
    base = _base(tmp_path)
    c = _FakeQemuImg()
    a = ensure_overlay(c, base=base, session_name="LIKE-DBG-a", image="i")
    b = ensure_overlay(c, base=base, session_name="LIKE-DBG-b", image="i")
    assert a != b
    assert a.is_file() and b.is_file()


def test_a_missing_base_is_reported_before_any_container_runs(tmp_path: Path) -> None:
    base = tmp_path / "artifacts" / "rootfs" / "gone.img"
    base.parent.mkdir(parents=True)
    c = _FakeQemuImg()
    with pytest.raises(RootfsError, match="rootfs image is missing"):
        ensure_overlay(c, base=base, session_name="s", image="i")
    assert c.execs == []


def test_a_qemu_img_that_produces_nothing_is_an_error_with_a_remedy(tmp_path: Path) -> None:
    base = _base(tmp_path)
    c = _FakeQemuImg(create=False)
    with pytest.raises(RootfsError) as exc:
        ensure_overlay(c, base=base, session_name="s", image="i")
    assert exc.value.remedy and "build-images" in exc.value.remedy


def test_overlays_for_finds_every_session_stacked_on_a_base(tmp_path: Path) -> None:
    base = _base(tmp_path)
    c = _FakeQemuImg()
    ensure_overlay(c, base=base, session_name="a", image="i")
    ensure_overlay(c, base=base, session_name="b", image="i")
    (base.parent / "unrelated.qcow2").write_bytes(b"x")
    assert [p.name for p in overlays_for(base)] == [f"{base.name}.a.qcow2", f"{base.name}.b.qcow2"]
