from likedbg.gdbcmd import resolve_debuginfod_enabled
from likedbg.host_profile import HostProfile


def _host():
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="x86_64",
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


def test_resolve_debuginfod_enabled():
    assert resolve_debuginfod_enabled("on", is_foreign=False) is True
    assert resolve_debuginfod_enabled("on", is_foreign=True) is True
    assert resolve_debuginfod_enabled("off", is_foreign=False) is False
    assert resolve_debuginfod_enabled("off", is_foreign=True) is False
    assert resolve_debuginfod_enabled("auto", is_foreign=True) is True
    assert resolve_debuginfod_enabled("auto", is_foreign=False) is False
