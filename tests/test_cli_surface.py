"""The CLI's own surface: `--help`, `--version`, and how `main` leaves on a Ctrl-C.

`start_kgdb --help` printed a bare list of 21 flags with no descriptions at all, and there was no
way to ask which version you were running even though the package carried one.
"""

import pytest

import likedbg.cli as cli
from likedbg import __version__
from likedbg.cli import build_parser


def test_every_option_documents_itself() -> None:
    """A flag that lands without `help=` is invisible in `--help`, which is where users look first."""
    undocumented = [a.option_strings for a in build_parser()._actions if not a.help]
    assert undocumented == []


def test_help_groups_flags_by_what_they_do(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for group in ("launching a session", "driving a live session", "inspecting", "maintenance"):
        assert group in out


def test_version_flag_reports_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_parser_still_accepts_the_flags_it_always_did() -> None:
    """Regrouping into argument groups must not change parsing: the groups are display-only."""
    args = build_parser().parse_args(
        ["-c", "lk01", "--profile", "kasan", "--run", "e.c", "--args=-v", "--prune", "30G", "--force-rebuild"]
    )
    assert args.config == "lk01"
    assert args.profile == "kasan"
    assert args.run == "e.c"
    # `--args=-v`, not `--args -v`: a dash-leading value has to be attached or argparse reads it as
    # a flag. Unchanged by the regrouping, but exactly the shape an exploit's own flags take.
    assert args.args == "-v"
    assert args.prune == "30G"
    assert args.force_rebuild is True


def test_bare_prune_still_means_use_the_configured_cap() -> None:
    assert build_parser().parse_args(["--prune"]).prune == ""
    assert build_parser().parse_args([]).prune is None


def test_explain_config_still_rejects_an_unknown_format() -> None:
    """The choices are shown via help text now, not a `{text,json}` metavar; they still bind."""
    assert build_parser().parse_args(["--explain-config"]).explain_config == "text"
    assert build_parser().parse_args(["--explain-config", "json"]).explain_config == "json"
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--explain-config", "yaml"])


def test_ctrl_c_exits_130_instead_of_dumping_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    """A kernel build runs for tens of minutes, so Ctrl-C out of one is routine, not a crash."""

    def _interrupt(*_args: object, **_kwargs: object) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "explain_config", _interrupt)
    assert cli.main(["--explain-config"]) == 130
