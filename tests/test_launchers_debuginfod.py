from pathlib import Path

from likedbg.constants import DEBUGINFOD_CACHE_MOUNT
from likedbg.launchers import gdb_pane_command


def _cmd(**kw):
    return gdb_pane_command(
        ["gdb-multiarch", "-q", "/w/vmlinux"],
        image="dbg:latest",
        mount_source="ksrc-vol",
        network_mode="published",
        **kw,
    )


def test_debuginfod_env_and_mount_when_set():
    cmd = _cmd(debuginfod_urls="https://debuginfod.elfutils.org", debuginfod_cache=Path("/w/artifacts/cache/debuginfod"))
    assert "-e DEBUGINFOD_URLS=https://debuginfod.elfutils.org" in cmd
    assert f"-e DEBUGINFOD_CACHE_PATH={DEBUGINFOD_CACHE_MOUNT}" in cmd
    assert f"/w/artifacts/cache/debuginfod:{DEBUGINFOD_CACHE_MOUNT}:rw" in cmd


def test_no_debuginfod_wiring_by_default():
    cmd = _cmd()
    assert "DEBUGINFOD" not in cmd
