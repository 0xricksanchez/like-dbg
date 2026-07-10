# Guards the shipped Pawnyable LK01 foreign scenario: the committed config must parse into faithful
# [foreign]/[debuggee] fields and drive the exact QEMU invocation the challenge's run.sh uses.
import tomllib
from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.config import ForeignCfg
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv

_SCENARIO = Path(__file__).resolve().parents[1] / "configs" / "scenarios" / "pawnyable-lk01.toml"
_CMDLINE = "console=ttyS0 loglevel=3 oops=panic panic=-1 nopti nokaslr"


def _sections() -> tuple[ForeignCfg, DebuggeeCfg]:
    with _SCENARIO.open("rb") as fh:
        data = tomllib.load(fh)
    return ForeignCfg(**data["foreign"]), DebuggeeCfg(**data["debuggee"])


def _host() -> HostProfile:
    return HostProfile(
        os="linux",
        host_arch="x86_64",
        target_arch="x86_64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="x",
    )


def test_pawnyable_lk01_scenario_parses_to_faithful_foreign_config() -> None:
    foreign, debuggee = _sections()
    assert foreign.image == "ctf/pawnyable-lk01/bzImage"
    assert foreign.initramfs == "ctf/pawnyable-lk01/rootfs.cpio"
    assert foreign.arch == "x86_64"
    assert foreign.cmdline == _CMDLINE  # verbatim challenge cmdline: nopti nokaslr -> all off
    assert debuggee.memory_mib == 64  # -m 64M
    assert debuggee.smep is False and debuggee.smap is False  # bare -cpu qemu64


def test_pawnyable_lk01_qemu_invocation_matches_challenge() -> None:
    foreign, debuggee = _sections()
    argv = build_qemu_argv(
        debuggee,
        _host(),
        target_arch="x86_64",
        kernel_image=Path(foreign.image),
        rootfs=Path(foreign.initramfs),
        foreign_cmdline=foreign.cmdline,
        qemu_extra=foreign.qemu_extra,
    )
    assert argv[argv.index("-cpu") + 1] == "qemu64"  # bare, no +smep/+smap
    assert argv[argv.index("-m") + 1] == "64"
    assert argv[argv.index("-initrd") + 1] == "ctf/pawnyable-lk01/rootfs.cpio"
    append = argv[argv.index("-append") + 1]
    assert append == _CMDLINE  # verbatim; console= already present, so not duplicated
    assert append.count("console=") == 1
