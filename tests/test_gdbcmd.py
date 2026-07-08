from pathlib import Path
from types import SimpleNamespace

import pytest

from likedbg.gdbcmd import build_gdb_args
from likedbg.host_profile import HostProfile


def _host(addr="host.docker.internal"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch="arm64",
        accel="hvf",
        debuggee_mode="native-host",
        storage_mode="volume",
        gdbstub_addr=addr,
    )


def _helper_arg(args):
    return next(arg for arg in args if "likedbg-reconnect" in arg)


def test_pwndbg_uses_target_remote_with_addr():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    s = " ".join(args)
    assert "target remote host.docker.internal:1234" in s
    assert "/w/vmlinux" in s
    # early-boot breakpoints must be hardware breakpoints (validated live)
    assert "hbreak start_kernel" in s
    # auto-load must be enabled before the symbol file loads
    assert "set auto-load safe-path /" in s


def test_safe_path_is_an_initial_command_before_the_file():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert args.index("-iex") < args.index("/w/vmlinux")


def test_gef_uses_gef_remote_not_qemu_user():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "gef-remote host.docker.internal 1234" in s
    assert "--qemu-user" not in s


def test_no_breakpoint_omits_break():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert "hbreak start_kernel" not in args
    assert "continue" not in args
    helper = _helper_arg(args)
    assert "breakpoint = None" in helper


def test_gef_sources_only_the_gef_plugin():
    # Both gef and pwndbg are installed in the image; the requested ext is sourced
    # explicitly (~/.gdbinit no longer auto-loads one) and the other must not appear.
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "source /opt/gef/gef.py" in s
    assert "/opt/pwndbg" not in s


def test_pwndbg_sources_only_the_pwndbg_plugin():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    s = " ".join(args)
    assert "source /opt/pwndbg/gdbinit.py" in s
    assert "/opt/gef" not in s


def test_extension_is_sourced_before_the_symbol_file():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert args.index("source /opt/gef/gef.py") < args.index("/w/vmlinux")


def test_sets_x86_64_gdb_architecture():
    args = build_gdb_args(_host(), arch="x86_64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert "set architecture i386:x86-64" in " ".join(args)


def test_sets_arm64_gdb_architecture():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    assert "set architecture aarch64" in " ".join(args)


def test_unknown_arch_raises_clear_error():
    with pytest.raises(ValueError, match="unsupported gdb architecture"):
        build_gdb_args(_host(), arch="riscv64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)


def test_remote_port_is_configurable():
    gef = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None, port=4444)
    assert "gef-remote host.docker.internal 4444" in " ".join(gef)
    pdb = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None, port=4444)
    assert "target remote host.docker.internal:4444" in " ".join(pdb)


def test_gef_reconnect_helper_disconnects_before_gef_remote():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert "likedbg-reconnect" in helper
    assert "disconnect" in helper
    assert "except gdb.error" in helper
    assert helper.index("disconnect") < helper.index("gef-remote host.docker.internal 1234")


def test_pwndbg_reconnect_helper_disconnects_before_target_remote():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert "likedbg-reconnect" in helper
    assert "disconnect" in helper
    assert "except gdb.error" in helper
    assert helper.index("disconnect") < helper.index("target remote host.docker.internal:1234")


def test_reconnect_helper_reapplies_initial_breakpoint_and_continues():
    args = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    helper = _helper_arg(args)
    assert '_set_pwndbg_context_sections("")' in helper
    assert "pwndbg.config.context_sections.value = value" in helper
    assert "set context-sections" in helper
    assert 'getattr(bp, "enabled", True)' in helper
    assert "if not _breakpoint_exists(breakpoint)" in helper
    assert 'hbreak " + breakpoint' in helper
    assert 'gdb.execute("continue", from_tty=from_tty)' in helper
    assert "hbreak start_kernel" in args
    assert "continue" in args


# ---------------------------------------------------------------------------
# Task 5: module-symbol stop-hook
# ---------------------------------------------------------------------------


def test_build_gdb_args_injects_module_hook_when_modules_gdb_set():
    from likedbg.gdbcmd import build_gdb_args

    args = build_gdb_args(
        _host(),
        arch="x86_64",
        vmlinux=Path("/ksrc/vmlinux"),
        ext="pwndbg",
        breakpoint="start_kernel",
        modules_gdb="/exploit/modules.gdb",
    )
    joined = " ".join(args)
    assert "/exploit/modules.gdb" in joined
    assert "events.stop" in joined or "hook" in joined  # a stop-driven reconcile


def test_build_gdb_args_no_module_hook_by_default():
    from likedbg.gdbcmd import build_gdb_args

    args = build_gdb_args(_host(), arch="x86_64", vmlinux=Path("/ksrc/vmlinux"), ext="pwndbg", breakpoint=None)
    assert "modules.gdb" not in " ".join(args)


def test_module_symbols_payload_reconciles_load_reload_unload(tmp_path):
    """Exercise the payload's reconcile logic directly (pure-python, no gdb): load -> reload (new
    addr, replace) -> unload (remove)."""
    from likedbg.gdbcmd import _reconcile_modules  # pure helper the payload calls

    log = tmp_path / "modules.gdb"
    log.write_text("load foo /exploit/modules/foo.ko 0x1000 .data 0x2000\n")
    applied = {}
    adds, removes = _reconcile_modules(log.read_text(), applied)
    assert adds == [("foo", "/exploit/modules/foo.ko", "0x1000", [(".data", "0x2000")])] and removes == []
    # reload at a new base
    log.write_text("load foo /exploit/modules/foo.ko 0x1000 .data 0x2000\nload foo /exploit/modules/foo.ko 0x9000\n")
    adds, removes = _reconcile_modules(log.read_text(), applied)
    assert ("foo", "/exploit/modules/foo.ko") in [(r[0], r[1]) for r in removes]
    assert any(a[2] == "0x9000" for a in adds)
    # unload
    log.write_text(log.read_text() + "unload foo\n")
    adds, removes = _reconcile_modules(log.read_text(), applied)
    assert removes and not adds and "foo" not in applied


def test_module_symbols_payload_reconciles_same_base_different_sections(tmp_path):
    """Regression: a reload at the SAME (ko, text) base but DIFFERENT sections (e.g. rebuild puts
    .data/.bss at new addresses while .text stays put — plausible under no-KASLR) must NOT be a
    silent no-op. The old entry must be removed and the new one (with the new sections) added."""
    from likedbg.gdbcmd import _reconcile_modules

    log = tmp_path / "modules.gdb"
    log.write_text("load foo /exploit/modules/foo.ko 0x1000\n")
    applied = {}
    adds, removes = _reconcile_modules(log.read_text(), applied)
    assert adds == [("foo", "/exploit/modules/foo.ko", "0x1000", [])] and removes == []

    # same (ko, text) base, but a new .data section appears — must not be a no-op
    log.write_text(log.read_text() + "load foo /exploit/modules/foo.ko 0x1000 .data 0x5000\n")
    adds, removes = _reconcile_modules(log.read_text(), applied)
    assert removes == [("foo", "/exploit/modules/foo.ko")]
    assert adds == [("foo", "/exploit/modules/foo.ko", "0x1000", [(".data", "0x5000")])]


def test_module_symbols_payload_is_valid_python_and_uses_reconcile_source():
    """The payload is `python exec(<source>)` — gdb only discovers a syntax error at launch time,
    so validate it with compile() here. Also assert the in-gdb `_reconcile` body is the *same*
    source as `_reconcile_modules` (inlined via inspect.getsource, not hand-duplicated)."""
    import ast
    import inspect

    from likedbg.gdbcmd import _module_symbols_source
    from likedbg.gdbcmd import _reconcile_modules

    payload = _module_symbols_source("/exploit/modules.gdb")
    assert payload.startswith("python exec(")
    assert payload.endswith(")")
    inner_repr = payload[len("python exec(") : -1]
    source = ast.literal_eval(inner_repr)  # the exec()'d source, recovered from its repr()
    compile(source, "<modules_gdb_payload>", "exec")  # raises SyntaxError if malformed
    assert "def _reconcile(" in source
    assert "def _reconcile_modules(" not in source  # renamed, not duplicated under both names
    assert "gdb.events.stop.connect(_sync)" in source
    # the pure function's body text (minus its def line) must appear verbatim in the payload
    pure_lines = inspect.getsource(_reconcile_modules).splitlines()
    body_lines = [line for line in pure_lines if not line.strip().startswith("def _reconcile_modules")]
    for line in body_lines:
        if line.strip() and not line.strip().startswith('"""') and '"""' not in line:
            assert line in source


class _FakeStopEvent:
    def __init__(self):
        self.callbacks = []

    def connect(self, fn):
        self.callbacks.append(fn)


class _FakeGdb:
    """Minimal stand-in for the real `gdb` module: just enough surface for the payload to
    `import gdb`, register a stop hook, and call execute()/write() when it fires."""

    def __init__(self):
        self.events = SimpleNamespace(stop=_FakeStopEvent())
        self.calls = []
        self.writes = []

    def execute(self, cmd, to_string=False):
        self.calls.append(cmd)
        return ""

    def write(self, msg):
        self.writes.append(msg)


def test_module_symbols_payload_execs_and_reconciles_against_a_fake_gdb(tmp_path, monkeypatch):
    """Beyond compile()-validity: actually exec() the extracted source against a stub `gdb` module
    and fire a simulated stop event, so a runtime error in the inlined/annotated reconcile function
    (not just a SyntaxError) would also be caught here."""
    import ast
    import sys

    from likedbg.gdbcmd import _module_symbols_source

    log = tmp_path / "modules.gdb"
    log.write_text("load foo /exploit/modules/foo.ko 0x1000 .data 0x2000\n")

    payload = _module_symbols_source(str(log))
    inner_repr = payload[len("python exec(") : -1]
    source = ast.literal_eval(inner_repr)

    fake_gdb = _FakeGdb()
    monkeypatch.setitem(sys.modules, "gdb", fake_gdb)
    namespace: dict = {}
    exec(compile(source, "<modules_gdb_payload>", "exec"), namespace)  # noqa: S102

    assert fake_gdb.events.stop.callbacks  # gdb.events.stop.connect(_sync) ran
    fake_gdb.events.stop.callbacks[0](None)  # simulate a stop event
    assert any(c == "add-symbol-file /exploit/modules/foo.ko 0x1000 -s .data 0x2000" for c in fake_gdb.calls)
    assert namespace["_APPLIED"] == {"foo": ("/exploit/modules/foo.ko", "0x1000", ((".data", "0x2000"),))}

    # unload: next stop must remove-symbol-file and drop it from _APPLIED
    log.write_text(log.read_text() + "unload foo\n")
    fake_gdb.events.stop.callbacks[0](None)
    assert any(c == "remove-symbol-file /exploit/modules/foo.ko" for c in fake_gdb.calls)
    assert namespace["_APPLIED"] == {}
