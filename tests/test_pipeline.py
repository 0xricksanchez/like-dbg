from loguru import logger

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext
from likedbg.pipeline import _fmt_duration


def _ctx():
    host = HostProfile(
        os="linux",
        host_arch="x86_64",
        target_arch="x86_64",
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="bind",
        gdbstub_addr="localhost",
    )
    return PipelineContext(settings=Settings(), host=host)


class RecordStage:
    def __init__(self, name, skip=False):
        self.name = name
        self._skip = skip
        self.ran = False

    def should_skip(self, ctx):
        return self._skip

    def run(self, ctx):
        self.ran = True
        ctx.kernel_status = self.name
        return ctx


def test_runs_stages_in_order():
    a, b = RecordStage("a"), RecordStage("b")
    Pipeline([a, b]).run(_ctx())
    assert a.ran and b.ran


def test_skips_when_should_skip_true():
    a = RecordStage("a", skip=True)
    Pipeline([a]).run(_ctx())
    assert a.ran is False


def test_context_threads_through():
    ctx = _ctx()
    out = Pipeline([RecordStage("download"), RecordStage("build")]).run(ctx)
    assert out.kernel_status == "build"  # last stage wrote it
    assert out is ctx


def test_fmt_duration():
    assert _fmt_duration(12) == "12s"
    assert _fmt_duration(59.9) == "59s"
    assert _fmt_duration(60) == "1m0s"
    assert _fmt_duration(220) == "3m40s"


def test_logs_stage_start_and_done():
    msgs = []
    sink = logger.add(msgs.append, level="INFO", format="{message}")
    try:
        Pipeline([RecordStage("build")]).run(_ctx())
        logger.complete()
    finally:
        logger.remove(sink)
    joined = "\n".join(msgs)
    assert "stage build: started" in joined
    assert "stage build: done (" in joined
