import json
import types

import pytest

from likedbg import cli
from likedbg.errors import LikeDbgError


def _mkrun(tmp_path):
    runs = tmp_path / "artifacts" / "runs" / "r1"
    (runs / "logs").mkdir(parents=True)
    (runs / "run.json").write_text(
        json.dumps(
            {
                "status": "launched",
                "build_label": "linux-6.6.30-x",
                "rootfs_label": "rootfs-arm64-x",
                "guest": {
                    "ssh_host": "127.0.0.1",
                    "ssh_port": 2222,
                    "share_mount": "/mnt/exploit",
                    "share_dir": "exploit",
                },
            }
        )
    )
    (runs / "host.json").write_text(json.dumps({"target_arch": "arm64", "storage_mode": "volume"}))
    reg = tmp_path / "artifacts" / "cache" / "rootfs"
    reg.mkdir(parents=True)
    (reg / "rootfs-arm64-x.json").write_text(
        json.dumps(
            {
                "kind": "rootfs",
                "label": "rootfs-arm64-x",
                "key": "k",
                "version": "",
                "arch": "arm64",
                "paths": {"image_host": "/w/r.img", "ssh_key": "/w/r.img.id_ed25519"},
            }
        )
    )
    (tmp_path / "exploit" / "modules").mkdir(parents=True)
    ko = tmp_path / "exploit" / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    (runs.parent / "latest").symlink_to(runs)
    return tmp_path, ko


def _patch_docker(monkeypatch):
    class FakeCS:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(cli, "ContainerService", FakeCS)
    monkeypatch.setattr(cli.docker_env, "make_client", lambda **k: object())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda **k: "unix://x")
    monkeypatch.setattr(
        cli,
        "resolve_toolchain",
        lambda comp, arch: types.SimpleNamespace(make_vars={"ARCH": arch, "LLVM": "1"}),
    )
    monkeypatch.setattr(
        cli.cache,
        "locations",
        lambda *a, **k: types.SimpleNamespace(kernel_root="/ksrc/x", gdb_mount_source="likedbg_ksrc"),
    )
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda ws: types.SimpleNamespace(
            settings=types.SimpleNamespace(build=types.SimpleNamespace(compiler="clang", custom_modules=()))
        ),
    )
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)


def test_cmd_insmod_stages_and_loads_prebuilt_ko(tmp_path, monkeypatch):
    ws, ko = _mkrun(tmp_path)
    _patch_docker(monkeypatch)
    captured: dict = {}

    def fake_stage(container, *, entry, out_dir, **kw):
        return entry if entry.suffix == ".ko" else out_dir / "lk01.ko"

    def fake_load(ep, ko_arg, *, name, share_dir, share_mount, args, reload, force_unload):
        captured.update(name=name, share_mount=share_mount, ko=ko_arg)
        return types.SimpleNamespace(rc=0, stdout="", stderr="")

    monkeypatch.setattr(cli, "stage_module", fake_stage)
    monkeypatch.setattr(cli.modules, "module_name", lambda c, k, *, image: "lk01")
    monkeypatch.setattr(cli.modules, "load", fake_load)
    rc = cli.cmd_insmod(ws, run_id="r1", path=str(ko), args="", force_unload=False)
    assert rc == 0
    assert captured["name"] == "lk01" and captured["share_mount"] == "/mnt/exploit"


def test_cmd_insmod_no_run_raises(tmp_path):
    with pytest.raises(LikeDbgError):
        cli.cmd_insmod(tmp_path, run_id="latest", path="", args="", force_unload=False)


def test_cmd_insmod_appends_load_event_from_sysfs(tmp_path, monkeypatch):
    tp, ko = _mkrun(tmp_path)
    _patch_docker(monkeypatch)
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)
    monkeypatch.setattr(cli.modules, "module_name", lambda *a, **k: "lk01")
    monkeypatch.setattr(cli.modules, "load", lambda *a, **k: types.SimpleNamespace(rc=0))
    monkeypatch.setattr(cli, "stage_module", lambda *a, **k: ko)
    # fake guest /sys read: .text + .data
    monkeypatch.setattr(
        cli.guest,
        "run",
        lambda ep, cmd, **k: types.SimpleNamespace(
            rc=0, stdout=".text 0xffffffffc0001000\n.data 0xffffffffc0003000\n", stderr=""
        ),
    )
    assert cli.cmd_insmod(tp, run_id="latest", path=str(ko.relative_to(tp)), args="", force_unload=False) == 0
    mg = (tp / "exploit" / "modules.gdb").read_text()
    assert mg.startswith("load lk01 /exploit/modules/") and "0xffffffffc0001000" in mg
    assert ".data 0xffffffffc0003000" in mg


def test_cmd_insmod_zeroed_text_falls_back_no_load_event(tmp_path, monkeypatch, capsys):
    """Regression: a kptr_restrict-hidden or non-root /sys/module/<n>/sections/.text read
    returns the literal string "0x0000000000000000", which is truthy — so pre-fix this wrote a
    `load ... 0x0000000000000000` event and gdb would add-symbol-file at address 0 (actively
    wrong symbols) instead of taking the graceful fallback."""
    tp, ko = _mkrun(tmp_path)
    _patch_docker(monkeypatch)
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)
    monkeypatch.setattr(cli.modules, "module_name", lambda *a, **k: "lk01")
    monkeypatch.setattr(cli.modules, "load", lambda *a, **k: types.SimpleNamespace(rc=0))
    monkeypatch.setattr(cli, "stage_module", lambda *a, **k: ko)
    # fake guest /sys read: all-zero .text (kptr_restrict-hidden / non-root)
    monkeypatch.setattr(
        cli.guest,
        "run",
        lambda ep, cmd, **k: types.SimpleNamespace(rc=0, stdout=".text 0x0000000000000000\n.data 0x0\n", stderr=""),
    )
    monkeypatch.setattr(cli.time, "sleep", lambda *_a, **_k: None)
    assert cli.cmd_insmod(tp, run_id="latest", path=str(ko.relative_to(tp)), args="", force_unload=False) == 0
    modules_gdb = tp / "exploit" / "modules.gdb"
    assert not modules_gdb.exists() or "load lk01" not in modules_gdb.read_text()
    out = capsys.readouterr().out
    assert "no .text section read" in out


def test_read_sections_retries_until_text_populated(monkeypatch):
    results = iter(
        [
            types.SimpleNamespace(rc=0, stdout=".data 0xffffffffc0003000\n", stderr=""),  # race: .text absent
            types.SimpleNamespace(
                rc=0, stdout=".text 0xffffffffc0001000\n.data 0xffffffffc0003000\n", stderr=""
            ),
        ]
    )
    monkeypatch.setattr(cli.guest, "run", lambda ep, cmd, **k: next(results))
    secs = cli._read_sections("ep", "lk01", attempts=3, sleep=lambda _s: None)
    assert (".text", "0xffffffffc0001000") in secs


def test_read_sections_gives_up_after_attempts(monkeypatch):
    monkeypatch.setattr(
        cli.guest,
        "run",
        lambda ep, cmd, **k: types.SimpleNamespace(rc=0, stdout=".data 0xffffffffc0003000\n", stderr=""),
    )
    secs = cli._read_sections("ep", "lk01", attempts=3, sleep=lambda _s: None)
    assert dict(secs).get(".text") is None


def test_cmd_rmmod_appends_unload_event(tmp_path, monkeypatch):
    tp, ko = _mkrun(tmp_path)
    (tp / "exploit").mkdir(exist_ok=True)
    (tp / "exploit" / "modules.gdb").write_text("load lk01 /exploit/modules/lk01.ko 0x1000\n")
    _patch_docker(monkeypatch)
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)
    monkeypatch.setattr(cli.modules, "unload", lambda *a, **k: types.SimpleNamespace(rc=0))
    assert cli.cmd_rmmod(tp, run_id="latest", name="lk01", force_unload=False) == 0
    assert (tp / "exploit" / "modules.gdb").read_text().splitlines()[-1] == "unload lk01"


def test_cmd_rmmod_failed_rc_does_not_append_unload_event(tmp_path, monkeypatch):
    """Regression: a FAILED rmmod (module busy, rc!=0) must not append an `unload` event —
    doing so would make the gdb hook drop symbols for a module that is still loaded."""
    tp, ko = _mkrun(tmp_path)
    (tp / "exploit").mkdir(exist_ok=True)
    (tp / "exploit" / "modules.gdb").write_text("load lk01 /exploit/modules/lk01.ko 0x1000\n")
    _patch_docker(monkeypatch)
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)
    monkeypatch.setattr(cli.modules, "unload", lambda *a, **k: types.SimpleNamespace(rc=1))
    assert cli.cmd_rmmod(tp, run_id="latest", name="lk01", force_unload=False) == 0
    text = (tp / "exploit" / "modules.gdb").read_text()
    assert "unload lk01" not in text
    assert text.splitlines()[-1] == "load lk01 /exploit/modules/lk01.ko 0x1000"
