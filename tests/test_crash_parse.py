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
    # The blank line sits BEFORE the RIP line so it guards BOTH halves: under the
    # old blank-line terminator it would null the event and drop fault_pc AND trace.
    log = (
        "[   12.345678] BUG: kernel NULL pointer dereference, address: 0000000000000000\r\n"
        "[   12.345684]\r\n"
        "[   12.345685] RIP: 0010:vuln_read+0x1a/0x40\r\n"
        "[   12.345687] RSP: 0018:ffffc90000abfe10 EFLAGS: 00010246\r\n"
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


def test_post_trace_tail_not_captured_as_frames() -> None:
    # The trace section ends at the first non-indented line. The standard x86 oops
    # tail (Modules linked in:, CR2:, ---[ end trace ]---, repeated RIP:/RSP:) is
    # column-0 and must NOT be scooped into ev.trace as bogus raw frames.
    log = (
        "[   12.345678] BUG: kernel NULL pointer dereference, address: 0000000000000000\r\n"
        "[   12.345685] RIP: 0010:vuln_read+0x1a/0x40\r\n"
        "[   12.345693] Call Trace:\r\n"
        "[   12.345694]  <TASK>\r\n"
        "[   12.345695]  vuln_ioctl+0x33/0x60\r\n"
        "[   12.345699]  do_syscall_64+0x5c/0x90\r\n"
        "[   12.345700]  </TASK>\r\n"
        "[   12.345701] Modules linked in: foo bar\r\n"
        "[   12.345702] CR2: 0000000000000000\r\n"
        "[   12.345703] ---[ end trace 0000000000000000 ]---\r\n"
        "[   12.345704] RIP: 0010:vuln_read+0x1a/0x40\r\n"
        "[   12.345705] RSP: 0018:ffffc90000abfe10 EFLAGS: 00010246\r\n"
    )
    events = parse_console(log, "x86_64")
    assert len(events) == 1
    ev = events[0]
    assert [f.symbol for f in ev.trace] == ["vuln_ioctl", "do_syscall_64"]
    raws = [f.raw for f in ev.trace]
    assert not any("CR2" in r for r in raws)
    assert not any("end trace" in r for r in raws)
    assert not any("Modules linked in" in r for r in raws)
    assert not any(r.startswith(("RIP:", "RSP:")) for r in raws)


def test_kasan_access_details() -> None:
    ev = parse_console(_read("kasan_uaf.txt"), "x86_64")[0]
    assert ev.kind == "kasan" and ev.fatal is True
    assert ev.kasan is not None
    assert ev.kasan.access == "read" and ev.kasan.size == 8
    assert ev.kasan.bad_addr == "ffff88800a1b2c00"
    assert "use-after-free" in ev.title
    # The fixture includes realistic "Allocated by task…"/"Freed by task…"
    # sub-sections. Those headers sit at column 0, so they end the main call
    # trace (indentation-gating) and are never re-entered since neither header
    # matches "Call Trace:"; ev.trace therefore holds only the main frames.
    assert [f.symbol for f in ev.trace] == ["kfree_test", "vuln_ioctl"]
    assert ev.incomplete is False


def test_ubsan_detected() -> None:
    ev = parse_console(_read("ubsan.txt"), "x86_64")[0]
    assert ev.kind == "ubsan" and ev.fatal is True
    assert "array-index-out-of-bounds" in ev.title


def test_warn_is_nonfatal() -> None:
    ev = parse_console(_read("warn.txt"), "x86_64")[0]
    assert ev.kind == "warn" and ev.fatal is False


def test_truncated_flagged_incomplete() -> None:
    ev = parse_console(_read("truncated.txt"), "x86_64")[0]
    assert ev.incomplete is True


def test_kernel_offset_complete_not_incomplete() -> None:
    # A COMPLETE x86 oops: "Kernel Offset: disabled" is standard panic-tail
    # boilerplate (prints under nokaslr, our default), NOT a truncation marker.
    # Combined with a proper "---[ end trace ]---" closing marker, this event
    # finished cleanly and must not be flagged incomplete.
    ev = parse_console(_read("kernel_offset_complete.txt"), "x86_64")[0]
    assert ev.kind == "oops" and ev.fatal is True
    assert ev.incomplete is False


def test_warn_then_oops_are_two_events() -> None:
    # A benign WARNING block that ends in "---[ end trace ]---", THEN a real fatal
    # oops. The end-marker must close the warn event so the BUG: onset opens a
    # SECOND event; the fatal oops (not the warn) must be primary.
    events = parse_console(_read("warn_then_oops.txt"), "x86_64")
    assert len(events) == 2
    assert events[0].kind == "warn" and events[0].fatal is False
    assert events[1].kind == "oops" and events[1].fatal is True
    assert events[1].fault_pc is not None and events[1].fault_pc.symbol == "vuln_read"
    assert [f.symbol for f in events[1].trace] == ["vuln_ioctl", "do_syscall_64"]
