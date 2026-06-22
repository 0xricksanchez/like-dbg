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
    debuggee, debugger = Session("LIKE-DBG", runner=rec).open_debug_layout()
    assert (debuggee, debugger) == (1, 2)
    joined = [" ".join(c) for c in rec.calls]
    assert any("splitw" in c for c in joined)
    assert sum("splitw" in c for c in joined) == 2  # two splits -> three panes
