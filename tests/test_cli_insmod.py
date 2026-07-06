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
