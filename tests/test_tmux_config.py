from pathlib import Path


def test_mouse_selection_copy_stays_in_copy_mode() -> None:
    config = (Path(__file__).resolve().parents[1] / ".tmux.conf").read_text()
    assert "bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe" in config
