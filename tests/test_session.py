import shlex
from pathlib import Path

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


def test_run_in_new_pane_full_adds_dash_f_for_full_window_split():
    # full=True inserts -f so the new pane spans the full window height (the Debugger's right column),
    # not just the target pane's size.
    checked_query = CheckedQueryRecorder(response="%3")
    pane = Session("LIKE-DBG", checked_query=checked_query).run_in_new_pane(
        target="%1",
        direction="h",
        percent=62,
        cmd="gdb",
        full=True,
    )
    assert pane == "%3"
    assert checked_query.calls == [
        [
            "tmux",
            "split-window",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            "-f",
            "-h",
            "-p",
            "62",
            "-t",
            "%1",
            "tmux set-option -p remain-on-exit on; exec gdb",
        ]
    ]


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


def test_pane_exists_uses_checked_query_status():
    ok = CheckedQueryRecorder(rc=0, response="%2")
    missing = CheckedQueryRecorder(rc=1)
    assert Session("LIKE-DBG", checked_query=ok).pane_exists("%2") is True
    assert Session("LIKE-DBG", checked_query=missing).pane_exists("%2") is False
    expected = ["tmux", "display-message", "-p", "-t", "%2", "#{pane_id}"]
    assert ok.calls == [expected]
    assert missing.calls == [expected]


def test_pane_exists_captures_tmux_output_instead_of_writing_to_active_pane():
    rec = Recorder()
    query = CheckedQueryRecorder(rc=0, response="%2")
    assert Session("LIKE-DBG", runner=rec, checked_query=query).pane_exists("%2") is True
    assert rec.calls == []


def test_display_message_calls_tmux_display_message():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).display_message("restarted Debuggee")
    assert rec.calls == [["tmux", "display-message", "restarted Debuggee"]]


def test_kill_pane_targets_only_the_requested_pane():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).kill_pane("%3")
    assert rec.calls == [["tmux", "kill-pane", "-t", "%3"]]


def test_session_has_no_shell_driving_layout_helpers():
    session = Session("LIKE-DBG")
    assert not hasattr(session, "split")
    assert not hasattr(session, "open_debug_layout")


def test_send_keys_issues_tmux_send_keys_with_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("%2", "echo hi")
    assert rec.calls == [["tmux", "send-keys", "-t", "%2", "echo hi", "Enter"]]


def test_send_keys_without_enter_omits_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("%2", "partial", enter=False)
    assert rec.calls == [["tmux", "send-keys", "-t", "%2", "partial"]]


def test_pane_base_index_falls_back_to_zero_when_unavailable():
    s = Session("X", runner=lambda a: 0, query=lambda a: "")
    assert s.pane_base_index() == 0


def test_pipe_pane_command(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    s = Session("LIKE-DBG", runner=lambda a: calls.append(a) or 0)
    out = tmp_path / "logs" / "debuggee-pane.log"
    s.pipe_pane(pane="%4", output=out)
    assert calls[0][:4] == ["tmux", "pipe-pane", "-o", "-t"]
    assert calls[0][4] == "%4"
    assert calls[0][5] == f"cat >> {shlex.quote(str(out))}"


# ---- multi-session: a name per boot, so a live session never blocks the next one ----


def test_unique_session_name_uses_the_base_when_free():
    from likedbg.session import unique_session_name

    assert unique_session_name("LIKE-DBG-lk01", []) == "LIKE-DBG-lk01"
    assert unique_session_name("LIKE-DBG-lk01", ["LIKE-DBG-lk02", "other"]) == "LIKE-DBG-lk01"


def test_unique_session_name_suffixes_past_a_live_session():
    """Regression: rename-session onto a name tmux already holds fails with 'duplicate session',
    which is how one leftover LIKE-DBG session blocked every subsequent run."""
    from likedbg.session import unique_session_name

    assert unique_session_name("LIKE-DBG-lk01", ["LIKE-DBG-lk01"]) == "LIKE-DBG-lk01-2"
    assert unique_session_name("LIKE-DBG-lk01", ["LIKE-DBG-lk01", "LIKE-DBG-lk01-2"]) == "LIKE-DBG-lk01-3"


def test_unique_session_name_skips_gaps_rather_than_reusing_them():
    from likedbg.session import unique_session_name

    taken = ["LIKE-DBG-x", "LIKE-DBG-x-2", "LIKE-DBG-x-3"]
    assert unique_session_name("LIKE-DBG-x", taken) == "LIKE-DBG-x-4"


def test_list_sessions_is_empty_without_a_tmux_server():
    from likedbg.session import Session

    s = Session("n", runner=lambda a: 0, query=lambda a: "", checked_query=lambda a: (1, ""))
    assert s.list_sessions() == []


def test_list_sessions_parses_one_name_per_line():
    from likedbg.session import Session

    s = Session("n", runner=lambda a: 0, query=lambda a: "alpha\nbeta\n", checked_query=lambda a: (0, ""))
    assert s.list_sessions() == ["alpha", "beta"]
