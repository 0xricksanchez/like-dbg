from pathlib import Path

from likedbg.guest import GuestEndpoint
from likedbg.guest import scp_argv
from likedbg.guest import ssh_argv
from likedbg.guest import wait_ready


def _ep():
    return GuestEndpoint(host="127.0.0.1", port=2222, key=Path("/w/rootfs.id_ed25519"))


def test_ssh_argv_has_key_flags_port():
    argv = ssh_argv(_ep(), "cd /mnt/exploit && ./poc")
    j = " ".join(argv)
    assert argv[0] == "ssh"
    assert "-i" in argv and "/w/rootfs.id_ed25519" in argv
    assert "-p" in argv and "2222" in argv
    assert "StrictHostKeyChecking=no" in j and "UserKnownHostsFile=/dev/null" in j
    # keepalive so a kernel-killing exploit (guest frozen under gdb) doesn't hang `run` forever
    assert "ServerAliveInterval=5" in j and "ServerAliveCountMax=3" in j
    assert argv[-2] == "root@127.0.0.1"
    assert argv[-1] == "cd /mnt/exploit && ./poc"


def test_scp_argv_target():
    argv = scp_argv(_ep(), Path("/w/exploit/poc"), "/mnt/exploit/poc")
    assert argv[0] == "scp" and "-P" in argv and "2222" in argv
    assert argv[-2] == "/w/exploit/poc" and argv[-1] == "root@127.0.0.1:/mnt/exploit/poc"


def test_wait_ready_polls_until_success():
    calls = {"n": 0}

    def runner(argv, **kw):
        calls["n"] += 1

        class R:
            returncode = 0 if calls["n"] >= 3 else 255

        return R()

    assert wait_ready(_ep(), timeout=100.0, runner=runner, sleep=lambda _s: None) is True
    assert calls["n"] == 3


def test_wait_ready_times_out():
    def runner(argv, **kw):
        class R:
            returncode = 255

        return R()

    assert wait_ready(_ep(), timeout=0.0, runner=runner, sleep=lambda _s: None) is False
