"""Regression coverage for the ``cmd_run`` lazy-container guarantee (ADR/task constraint):
a Docker ``ContainerService`` + image ensure must be constructed ONLY when the exploit path
ends ``.c`` (needs an in-container compile). A prebuilt-binary ``--run ./expl`` must touch no
Docker at all — not even to build a client. See src/likedbg/cli.py::cmd_run.

These tests make the guarantee environment-independent: they patch every Docker entry point to
raise loudly if invoked, so the test fails even on a host where Docker happens to be running and
would otherwise silently "work" despite a regression that moved container construction outside
the ``.c`` guard.
"""

import json
import types

from likedbg import cli


def _mkrun(tmp_path, run_id="r1"):
    """Minimal run dir with a guest block + a rootfs manifest carrying an ssh_key (mirrors
    tests/test_cli_insmod.py::_mkrun / tests/test_exploit.py::_mk_run_with_guest)."""
    runs = tmp_path / "artifacts" / "runs" / run_id
    (runs / "logs").mkdir(parents=True)
    (runs / "exploit").mkdir()
    (runs / "run.json").write_text(
        json.dumps(
            {
                "status": "launched",
                "build_label": "linux-6.6.30-x",
                "rootfs_label": "rootfs-x86_64-x",
                "guest": {
                    "ssh_host": "127.0.0.1",
                    "ssh_port": 2222,
                    "share_mount": "/mnt/exploit",
                    "share_dir": "exploit",
                },
            }
        )
    )
    (runs / "host.json").write_text(json.dumps({"target_arch": "x86_64", "storage_mode": "volume"}))
    reg = tmp_path / "artifacts" / "cache" / "rootfs"
    reg.mkdir(parents=True)
    (reg / "rootfs-x86_64-x.json").write_text(
        json.dumps(
            {
                "kind": "rootfs",
                "label": "rootfs-x86_64-x",
                "key": "k",
                "version": "",
                "arch": "x86_64",
                "paths": {"image_host": "/w/r.img", "ssh_key": "/w/r.img.id_ed25519"},
            }
        )
    )
    (tmp_path / "exploit").mkdir(parents=True)
    return tmp_path


def _boom(what):
    def _raise(*_a, **_k):
        raise AssertionError(f"binary --run must NOT {what}")

    return _raise


def _forbid_docker(monkeypatch):
    """Make any Docker construction fail loudly, regardless of whether a real Docker daemon is
    reachable on the test host."""
    monkeypatch.setattr(cli, "ContainerService", _boom("construct a container"))
    monkeypatch.setattr(cli.docker_env, "make_client", _boom("touch Docker (make_client)"))
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", _boom("touch Docker (resolve_docker_host)"))


def test_cmd_run_binary_path_never_touches_docker(tmp_path, monkeypatch):
    ws = _mkrun(tmp_path)
    _forbid_docker(monkeypatch)
    expl = ws / "exploit" / "expl"
    expl.write_bytes(b"\x7fELF")

    seen: dict = {}

    def fake_run_exploit(_workspace, _run_id, _exploit, _args, *, container=None):
        seen["container"] = container
        return 0

    monkeypatch.setattr(cli, "run_exploit", fake_run_exploit)

    rc = cli.cmd_run(ws, run_id="r1", exploit=str(expl), args="")

    assert rc == 0
    assert seen["container"] is None


def test_cmd_run_c_path_constructs_container(tmp_path, monkeypatch):
    ws = _mkrun(tmp_path)
    src = ws / "exploit" / "expl.c"
    src.write_text("int main(void){return 0;}\n")

    dummy_client = object()
    dummy_container = types.SimpleNamespace(marker="container")

    monkeypatch.setattr(cli.docker_env, "make_client", lambda **_k: dummy_client)
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda **_k: "unix://x")
    monkeypatch.setattr(cli, "ContainerService", lambda client: dummy_container if client is dummy_client else None)
    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: None)

    seen: dict = {}

    def fake_run_exploit(_workspace, _run_id, _exploit, _args, *, container=None):
        seen["container"] = container
        return 0

    monkeypatch.setattr(cli, "run_exploit", fake_run_exploit)

    rc = cli.cmd_run(ws, run_id="r1", exploit=str(src), args="")

    assert rc == 0
    assert seen["container"] is dummy_container
