import pytest

from likedbg.errors import SessionError
from likedbg.session import Session


class Recorder:
    def __init__(self, rc=0):
        self.calls: list[list[str]] = []
        self.rc = rc

    def __call__(self, args: list[str]) -> int:
        self.calls.append(args)
        return self.rc


def test_select_pane_issues_tmux_selectp():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).select_pane(2)
    assert rec.calls == [["tmux", "selectp", "-t", "2"]]


def test_split_horizontal_with_percent():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).split("h", 50)
    assert rec.calls == [["tmux", "splitw", "-h", "-p", "50"]]


def test_send_keys_appends_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("echo hi")
    assert rec.calls == [["tmux", "send-keys", "echo hi", "C-m"]]


def test_nonzero_runner_raises_sessionerror():
    rec = Recorder(rc=1)
    with pytest.raises(SessionError):
        Session("LIKE-DBG", runner=rec).select_pane(0)


def test_open_debug_layout_splits_into_three_panes():
    rec = Recorder()
    debuggee, debugger = Session("LIKE-DBG", runner=rec, query=lambda a: "0").open_debug_layout()
    assert (debuggee, debugger) == (1, 2)
    joined = [" ".join(c) for c in rec.calls]
    assert any("splitw" in c for c in joined)
    assert sum("splitw" in c for c in joined) == 2  # two splits -> three panes


def test_open_debug_layout_honors_pane_base_index_one():
    # On tmux configured with `pane-base-index 1`, the panes are 1/2/3, not 0/1/2.
    rec = Recorder()
    debuggee, debugger = Session("LIKE-DBG", runner=rec, query=lambda a: "1").open_debug_layout()
    assert (debuggee, debugger) == (2, 3)
    joined = [" ".join(c) for c in rec.calls]
    assert any("selectp -t 1" in c for c in joined)  # selects the base pane, not pane 0
    assert not any("selectp -t 0" in c for c in joined)  # never touches a nonexistent pane 0
    assert sum("splitw" in c for c in joined) == 2


def test_pane_base_index_falls_back_to_zero_when_unavailable():
    s = Session("X", runner=lambda a: 0, query=lambda a: "")
    assert s.pane_base_index() == 0
