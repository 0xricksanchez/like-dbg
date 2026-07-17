import pytest
from loguru import logger

from likedbg import logsetup


@pytest.fixture(autouse=True)
def _restore_logger():
    # logsetup mutates the global loguru logger; snapshot handler ids and restore after each test.
    before = set(logger._core.handlers)  # noqa: SLF001
    yield
    for hid in set(logger._core.handlers) - before:  # noqa: SLF001
        logger.remove(hid)


def test_configure_stderr_sets_level_by_verbose():
    logsetup.configure_stderr(verbose=False)
    levels = [h.levelno for h in logger._core.handlers.values()]  # noqa: SLF001
    assert levels == [20]  # INFO, with old sinks removed
    logsetup.configure_stderr(verbose=True)
    levels = [h.levelno for h in logger._core.handlers.values()]  # noqa: SLF001
    assert levels == [10]  # DEBUG, with the prior INFO sink removed


def test_add_run_logfile_creates_file_latest_and_captures_debug(tmp_path):
    run_log = logsetup.add_run_logfile(tmp_path)
    assert run_log.parent == tmp_path / "artifacts" / "logs"
    assert run_log.name.startswith("run-") and run_log.suffix == ".log"
    logger.debug("hello-marker")
    logger.complete()
    assert "hello-marker" in run_log.read_text()
    latest = tmp_path / "artifacts" / "logs" / "latest.log"
    assert latest.is_symlink() and latest.resolve() == run_log.resolve()


def test_add_run_logfile_external_path_points_latest_at_run_scoped_log(tmp_path):
    run_log = tmp_path / "artifacts" / "runs" / "run-123" / "logs" / "likedbg.log"
    logsetup.add_run_logfile(tmp_path, path=run_log)
    latest = tmp_path / "artifacts" / "logs" / "latest.log"
    assert latest.is_symlink() and latest.resolve() == run_log.resolve()


def test_prune_old_logs_keeps_newest(tmp_path):
    logs = tmp_path / "artifacts" / "logs"
    logs.mkdir(parents=True)
    for i in range(22):
        (logs / f"run-20260624T0000{i:02d}Z.log").write_text("x")
    logsetup._prune_old_logs(logs, keep=20)  # noqa: SLF001
    remaining = sorted(p.name for p in logs.glob("run-*.log"))
    assert len(remaining) == 20
    assert remaining[0] == "run-20260624T000002Z.log"  # the 2 oldest pruned
