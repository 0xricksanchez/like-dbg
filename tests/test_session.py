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


class QueryRecorder:
    def __init__(self, response: str):
        self.calls: list[list[str]] = []
        self.response = response

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self.response


class CheckedQueryRecorder:
    def __init__(self, rc: int = 0, response: str = ""):
        self.calls: list[list[str]] = []
        self.rc = rc
        self.response = response

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(args)
        return self.rc, self.response


def test_select_pane_issues_tmux_selectp():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).select_pane(2)
    assert rec.calls == [["tmux", "selectp", "-t", "2"]]


def test_run_in_new_pane_splits_detached_returns_pane_and_sets_remain_on_exit():
    rec = Recorder()
    checked_query = CheckedQueryRecorder(response="%2")
    pane = Session("LIKE-DBG", runner=rec, checked_query=checked_query).run_in_new_pane(
        target="%1",
        direction="h",
        percent=66,
        cmd="echo hi",
    )
    assert pane == "%2"
    assert checked_query.calls == [
        [
            "tmux",
            "split-window",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            "-h",
            "-p",
            "66",
            "-t",
            "%1",
            "tmux set-option -p remain-on-exit on; exec echo hi",
        ]
    ]
    assert rec.calls == []


def test_run_in_new_pane_raises_when_split_fails():
    checked_query = CheckedQueryRecorder(rc=1)
    with pytest.raises(SessionError):
        Session("LIKE-DBG", checked_query=checked_query).run_in_new_pane(
            target="%1",
            direction="h",
            percent=66,
            cmd="echo hi",
        )


def test_nonzero_runner_raises_sessionerror():
    rec = Recorder(rc=1)
    with pytest.raises(SessionError):
        Session("LIKE-DBG", runner=rec).select_pane(0)


def test_respawn_pane_reasserts_remain_on_exit():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).respawn_pane(pane="%2", cmd="qemu-system-aarch64")
    assert rec.calls == [
        ["tmux", "set-option", "-p", "-t", "%2", "remain-on-exit", "on"],
        ["tmux", "respawn-pane", "-k", "-t", "%2", "qemu-system-aarch64"],
    ]


def test_current_pane_id_queries_tmux():
    query = QueryRecorder("%1")
    assert Session("LIKE-DBG", query=query).current_pane_id() == "%1"
    assert query.calls == [["tmux", "display-message", "-p", "#{pane_id}"]]


def test_session_options_use_current_session_scope():
    rec = Recorder()
    query = QueryRecorder("/tmp/work")
    session = Session("LIKE-DBG", runner=rec, query=query)
    assert session.get_option("@likedbg_workspace") == "/tmp/work"
    session.set_option("@likedbg_workspace", "/tmp/work")
    session.unset_option("@likedbg_restart_in_progress")
    assert query.calls == [["tmux", "show-option", "-qv", "@likedbg_workspace"]]
    assert rec.calls == [
        ["tmux", "set-option", "@likedbg_workspace", "/tmp/work"],
        ["tmux", "set-option", "-u", "@likedbg_restart_in_progress"],
    ]


def test_pane_exists_uses_runner_status():
    ok = Recorder(rc=0)
    missing = Recorder(rc=1)
    assert Session("LIKE-DBG", runner=ok).pane_exists("%2") is True
    assert Session("LIKE-DBG", runner=missing).pane_exists("%2") is False
    expected = ["tmux", "display-message", "-p", "-t", "%2", "#{pane_id}"]
    assert ok.calls == [expected]
    assert missing.calls == [expected]


def test_display_message_calls_tmux_display_message():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).display_message("restarted Debuggee")
    assert rec.calls == [["tmux", "display-message", "restarted Debuggee"]]


def test_session_has_no_shell_driving_layout_helpers():
    session = Session("LIKE-DBG")
    assert not hasattr(session, "send_keys")
    assert not hasattr(session, "split")
    assert not hasattr(session, "open_debug_layout")


def test_pane_base_index_falls_back_to_zero_when_unavailable():
    s = Session("X", runner=lambda a: 0, query=lambda a: "")
    assert s.pane_base_index() == 0
