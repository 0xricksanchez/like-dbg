"""The scenarios in configs/scenarios/ are documentation that executes.

A scenario's header claims a specific guest; docs/ctf-foreign-kernel.md repeats the claim. Nothing
re-checks either against what QEMU is actually told, so a local experiment can be committed on top
of a shipped example and the prose keeps promising the old guest. That happened: a WIP snapshot
flipped LK01's smep/smap and added kaslr/kpti toggles, and the flagship worked example booted fully
mitigated while its own comments said every mitigation was off.
"""

import tomllib
from pathlib import Path

from likedbg.config import DebuggeeCfg
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv

_SCENARIOS = Path(__file__).resolve().parents[1] / "configs" / "scenarios"


def _boot(name: str) -> tuple[list[str], str]:
    """(argv, -append) for a shipped foreign scenario, resolved the way a real boot resolves it.

    The [debuggee] keys the scenario sets are exactly the ones provenance marks "scenario", which is
    what makes them explicit overrides -- so passing them as foreign_mitigation_overrides mirrors the
    run. Read straight off disk rather than through load_config: a personal (gitignored) configs/
    local.toml must not be able to change what this test sees.
    """
    doc = tomllib.loads((_SCENARIOS / f"{name}.toml").read_text(encoding="utf-8"))
    debuggee = doc.get("debuggee", {})
    foreign = doc["foreign"]
    host = HostProfile(
        os="linux",
        host_arch="x86_64",
        target_arch="x86_64",
        accel="kvm",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="localhost",
    )
    argv = build_qemu_argv(
        DebuggeeCfg(**debuggee, guest_net=False, share=False),
        host,
        target_arch=foreign["arch"],
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline=foreign["cmdline"],
        foreign_mitigation_overrides=set(debuggee),
    )
    return argv, argv[argv.index("-append") + 1]


def test_pawnyable_lk01_boots_the_guest_its_header_and_the_docs_promise() -> None:
    """LK01 "Holstein v1" is ret2usr against a bare -cpu qemu64; +smep alone breaks the exploit."""
    argv, append = _boot("pawnyable-lk01")

    assert "qemu64" in argv
    assert "+smep" not in argv[argv.index("-cpu") + 1]
    assert "+smap" not in argv[argv.index("-cpu") + 1]
    # The challenge disables KASLR/KPTI in its own cmdline, which LIKE-DBG passes verbatim. A
    # [debuggee] kaslr/kpti toggle would instead rewrite that cmdline -- adding "kaslr pti=on" here.
    assert "nopti" in append.split()
    assert "nokaslr" in append.split()
    assert "pti=on" not in append
    assert "kaslr" not in append.split()


def test_pawnyable_lk01_passes_the_challenge_cmdline_through_untouched() -> None:
    """The whole point of the foreign path: what the challenge boots with is what the guest gets."""
    doc = tomllib.loads((_SCENARIOS / "pawnyable-lk01.toml").read_text(encoding="utf-8"))
    _argv, append = _boot("pawnyable-lk01")
    assert append == doc["foreign"]["cmdline"]
