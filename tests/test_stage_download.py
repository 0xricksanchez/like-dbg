from loguru import logger

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.download import DownloadStage
from likedbg.stages.download import archive_url
from likedbg.stages.download import resolve_version


def _ctx(tmp_path, **dl):
    settings = Settings.model_validate({"kernel_dl": dl})
    host = HostProfile(
        os="linux",
        host_arch="arm64",
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
        ssh_addr="localhost",
    )
    return PipelineContext(settings=settings, host=host)


def test_resolve_version_priority_mmp_over_tag():
    from likedbg.config import KernelDlCfg

    assert resolve_version(KernelDlCfg(mmp="6.6.30", tag="6.6")) == "6.6.30"


def test_archive_url_mmp_uses_cdn_xz():
    url = archive_url("6.6.30")
    assert url.endswith("linux-6.6.30.tar.xz")
    assert "cdn.kernel.org" in url


def test_download_runs_fetcher_and_sets_archive(tmp_path):
    calls = []
    stage = DownloadStage(lambda url, dest: calls.append((url, dest)) or dest.write_bytes(b"x"), dl_dir=tmp_path)
    ctx = _ctx(tmp_path, tag="6.6")
    out = stage.run(ctx)
    assert out.kernel_archive is not None and out.kernel_archive.exists()
    assert len(calls) == 1


def test_download_idempotent_when_archive_present(tmp_path):
    # A cached archive must not be re-fetched, but the stage must still run so it can
    # record kernel_archive in the context for the Unpack stage.
    calls = []
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    stage = DownloadStage(lambda url, dest: calls.append((url, dest)), dl_dir=tmp_path)
    ctx = _ctx(tmp_path, tag="6.6")
    (tmp_path / "linux-6.6.tar.gz").write_bytes(b"x")
    try:
        assert stage.should_skip(ctx) is False
        out = stage.run(ctx)
        logger.complete()
    finally:
        logger.remove(sink)
    assert out.kernel_archive == tmp_path / "linux-6.6.tar.gz"
    assert calls == []  # no re-fetch
    assert any("download cache hit: linux-6.6.tar.gz" in m for m in msgs)
