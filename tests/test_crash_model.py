from likedbg.crash.model import CrashEvent
from likedbg.crash.model import CrashReport
from likedbg.crash.model import Frame
from likedbg.crash.model import GdbLive


def test_event_to_dict_renames_kind_to_class():
    ev = CrashEvent(kind="kasan", fatal=True, title="use-after-free")
    d = ev.to_dict()
    assert d["class"] == "kasan"
    assert "kind" not in d
    assert d["fatal"] is True and d["source"] == ["console"]


def test_report_to_dict_derives_sources_and_primary():
    ev = CrashEvent(
        kind="oops",
        fatal=True,
        title="BUG",
        trace=[Frame(raw="a+0x1/0x2", symbol="a", offset=1)],
        gdb_live=GdbLive(stopped_at="die", registers={"pc": "0x1"}, backtrace=["#0 die"]),
        source=["console", "gdb-live"],
    )
    rep = CrashReport(arch="x86_64", build_label="linux-6.6.30-x", kernel_release="6.6.30", events=[ev], primary=0)
    d = rep.to_dict()
    assert d["schema_version"] == 1 and d["primary"] == 0
    assert d["sources"] == ["console", "gdb-live"]
    assert d["events"][0]["gdb_live"]["stopped_at"] == "die"
    assert d["events"][0]["trace"][0]["symbol"] == "a"
