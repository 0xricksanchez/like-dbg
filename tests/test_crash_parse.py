from pathlib import Path

from likedbg.crash.parse import normalize
from likedbg.crash.parse import parse_console

FIX = Path(__file__).parent / "fixtures" / "crash"


def _read(name: str) -> str:
    # read_bytes().decode() preserves literal CRLF (read_text applies
    # universal-newline translation, which would hide the x86 fixture's \r\n).
    return (FIX / name).read_bytes().decode()


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


def test_timestamp_only_line_does_not_drop_fault_pc_or_trace() -> None:
    # A realistic dmesg timestamp-only line strips to empty mid-dump; it must NOT
    # close the open event and swallow the RIP + trace that follow it.
    log = (
        "[   12.345678] BUG: kernel NULL pointer dereference, address: 0000000000000000\r\n"
        "[   12.345685] RIP: 0010:vuln_read+0x1a/0x40\r\n"
        "[   12.345687] RSP: 0018:ffffc90000abfe10 EFLAGS: 00010246\r\n"
        "[   12.345688]\r\n"
        "[   12.345693] Call Trace:\r\n"
        "[   12.345695]  vuln_ioctl+0x33/0x60\r\n"
        "[   12.345699]  do_syscall_64+0x5c/0x90\r\n"
    )
    events = parse_console(log, "x86_64")
    assert len(events) == 1
    ev = events[0]
    assert ev.fault_pc is not None and ev.fault_pc.symbol == "vuln_read"
    assert [f.symbol for f in ev.trace] == ["vuln_ioctl", "do_syscall_64"]


def test_raw_hex_trace_frames_kept_and_task_markers_ignored() -> None:
    # Non-symbolic frames (old-style "[<addr>] ? func+.." and a bare hex address)
    # are kept raw with symbol None; "<TASK>"/"</TASK>" markers are NOT captured.
    log = (
        "[    1.000000] BUG: kernel NULL pointer dereference, address: 0000000000000000\r\n"
        "[    1.000001] RIP: 0010:vuln_read+0x1a/0x40\r\n"
        "[    1.000002] Call Trace:\r\n"
        "[    1.000003]  <TASK>\r\n"
        "[    1.000004]  [<ffffffff81234567>] ? some_func+0x1/0x2\r\n"
        "[    1.000005]  ffffffff89abcdef\r\n"
        "[    1.000006]  do_syscall_64+0x5c/0x90\r\n"
        "[    1.000007]  </TASK>\r\n"
    )
    events = parse_console(log, "x86_64")
    assert len(events) == 1
    ev = events[0]
    assert not any("TASK" in f.raw for f in ev.trace)
    assert any(f.symbol is None and "[<ffffffff81234567>]" in f.raw for f in ev.trace)
    assert any(f.symbol is None and f.raw == "ffffffff89abcdef" for f in ev.trace)
    assert any(f.symbol == "do_syscall_64" for f in ev.trace)
