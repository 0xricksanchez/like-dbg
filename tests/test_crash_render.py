from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport
from likedbg.crash.model import Frame
from likedbg.crash.model import KasanInfo
from likedbg.crash.render import render_json
from likedbg.crash.render import render_markdown


def _report():
    ev = CrashEvent(
        kind="kasan",
        fatal=True,
        title="BUG: KASAN: use-after-free in kfree_test+0x120/0x180",
        kasan=KasanInfo(access="read", size=8, bad_addr="ffff88800a1b2c00"),
        fault_pc=Frame(raw="kfree_test+0x120/0x180", symbol="kfree_test", offset=288),
        trace=[Frame(raw="vuln_ioctl+0x40/0x70", symbol="vuln_ioctl", offset=64)],
        source=["console"],
    )
    return CrashReport(arch="x86_64", build_label="linux-6.6.30-x", kernel_release="6.6.30", events=[ev], primary=0)


def test_render_json_matches_to_dict():
    rep = _report()
    assert render_json(rep) == rep.to_dict()


def test_render_markdown_has_key_sections():
    md = render_markdown(_report())
    assert "# Crash report" in md
    assert "use-after-free" in md
    assert "kfree_test" in md
    assert "read" in md and "ffff88800a1b2c00" in md
    assert "vuln_ioctl" in md
