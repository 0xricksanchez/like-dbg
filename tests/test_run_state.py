import json
from pathlib import Path

import pytest

from likedbg.errors import ModuleError
from likedbg.run_state import guest_endpoint
from likedbg.run_state import is_foreign_run
from likedbg.run_state import read_run_state

_GUEST = {"ssh_host": "127.0.0.1", "ssh_port": 2222, "share_dir": "exploit", "share_mount": "/mnt/exploit"}


def _run_dir(tmp_path: Path, run_json: object | None) -> Path:
    d = tmp_path / "runs" / "r1"
    d.mkdir(parents=True)
    if run_json is not None:
        (d / "run.json").write_text(run_json if isinstance(run_json, str) else json.dumps(run_json))
    return d


# ---- reading run artifacts: a half-written run dir must not surface as a traceback ----


def test_read_run_state_returns_the_parsed_object(tmp_path: Path) -> None:
    d = _run_dir(tmp_path, {"build_label": "linux-6.6.30-abc"})
    assert read_run_state(d, "run.json", error=ModuleError)["build_label"] == "linux-6.6.30-abc"


def test_missing_run_json_raises_a_typed_error_not_filenotfound(tmp_path: Path) -> None:
    """Regression: a RunRecorder interrupted between mkdir and its first write leaves exactly
    this, and it used to reach the user as a raw FileNotFoundError."""
    d = _run_dir(tmp_path, None)
    with pytest.raises(ModuleError) as exc:
        read_run_state(d, "run.json", error=ModuleError)
    assert "not readable" in str(exc.value) and exc.value.remedy


def test_corrupt_run_json_raises_a_typed_error_not_jsondecodeerror(tmp_path: Path) -> None:
    d = _run_dir(tmp_path, '{"guest": ')
    with pytest.raises(ModuleError) as exc:
        read_run_state(d, "run.json", error=ModuleError)
    assert "corrupt" in str(exc.value) and exc.value.remedy


def test_non_object_run_json_is_rejected(tmp_path: Path) -> None:
    d = _run_dir(tmp_path, "[1, 2, 3]")
    with pytest.raises(ModuleError):
        read_run_state(d, "run.json", error=ModuleError)


# ---- refusing a command the run cannot serve, with a remedy that is actually possible ----


def test_guest_endpoint_returns_the_block_when_present() -> None:
    ep = guest_endpoint({"guest": _GUEST}, error=ModuleError, foreign_remedy="unused")
    assert ep["ssh_port"] == 2222


def test_foreign_run_refuses_without_suggesting_guest_net() -> None:
    """Regression: every no-guest refusal said 'boot with guest_net enabled', but cmd_foreign
    forces guest_net=False by design (ADR-0010) -- an adopted challenge ships no sshd. That
    remedy sent the operator after something the design will never give them."""
    with pytest.raises(ModuleError) as exc:
        guest_endpoint(
            {"build_label": "foreign-pawnyable-lk01"}, error=ModuleError, foreign_remedy="use --upload instead"
        )
    assert "guest_net" not in str(exc.value) and "guest_net" not in (exc.value.remedy or "")
    assert exc.value.remedy == "use --upload instead"


def test_built_run_without_a_guest_still_points_at_guest_net() -> None:
    """The old remedy is right for a self-built run: there, guest_net genuinely is the switch."""
    with pytest.raises(ModuleError) as exc:
        guest_endpoint({"build_label": "linux-6.6.30-abc"}, error=ModuleError, foreign_remedy="n/a")
    assert "guest_net" in (exc.value.remedy or "")


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("foreign-pawnyable-lk01", True),
        ("linux-6.6.30-abc", False),
        ("", False),
    ],
)
def test_is_foreign_run_keys_on_the_label_prefix(label: str, expected: bool) -> None:
    assert is_foreign_run({"build_label": label}) is expected


def test_is_foreign_run_tolerates_a_missing_label() -> None:
    assert is_foreign_run({}) is False
