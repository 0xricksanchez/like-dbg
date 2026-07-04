from pathlib import Path

from likedbg.crash.parse import normalize
from likedbg.crash.parse import parse_console

FIX = Path(__file__).parent / "fixtures" / "crash"


def _read(name: str) -> str:
    return (FIX / name).read_text()


def test_normalize_strips_crlf() -> None:
    assert normalize("a\r\nb\rc\n") == "a\nb\nc\n"


def test_x86_oops_classified_with_rip_and_trace() -> None:
    events = parse_console(_read("x86_oops.txt"), "x86_64")
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "oops" and ev.fatal is True
    assert ev.fault_pc is not None and ev.fault_pc.symbol == "vuln_read"
    assert ev.fault_addr == "0000000000000000"
    assert [f.symbol for f in ev.trace] == ["vuln_ioctl", "__x64_sys_ioctl", "do_syscall_64"]
    assert ev.registers.get("RSP", "").startswith("0018:")


def test_arm64_oops_uses_pc_line_and_call_trace() -> None:
    events = parse_console(_read("arm64_oops.txt"), "arm64")
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "oops"
    assert ev.fault_pc is not None and ev.fault_pc.symbol == "vuln_read"
    assert [f.symbol for f in ev.trace][:2] == ["vuln_read", "vuln_ioctl"]


def test_panic_detected() -> None:
    events = parse_console(_read("panic.txt"), "x86_64")
    assert len(events) == 1 and events[0].kind == "panic" and events[0].fatal is True
    assert "sysrq triggered crash" in events[0].title
