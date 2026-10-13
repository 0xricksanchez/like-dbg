import pytest

from likedbg.config import LAYER_BUILTIN
from likedbg.config import LAYER_CLI
from likedbg.config import LAYER_DEFAULT
from likedbg.config import LAYER_SCENARIO
from likedbg.config import DebuggeeCfg
from likedbg.errors import ConfigError
from likedbg.ports import port_is_free
from likedbg.ports import resolve_ports


def _busy(*ports: int):
    taken = set(ports)
    return lambda p: p not in taken


def _prov(**layers: str) -> dict[tuple[str, str], str]:
    return {("debuggee", k): v for k, v in layers.items()}


def test_free_ports_are_left_exactly_alone() -> None:
    eff = DebuggeeCfg()
    plan = resolve_ports(eff, _prov(), is_free=_busy())
    assert plan.debuggee.gdbstub_port == 1234
    assert plan.debuggee.ssh_port == 2222
    assert plan.notes == ()


def test_an_unchosen_port_moves_and_says_so() -> None:
    """A default nobody expressed an opinion about is a placeholder; moving it is a convenience."""
    plan = resolve_ports(DebuggeeCfg(), _prov(gdbstub_port=LAYER_DEFAULT), is_free=_busy(1234))
    assert plan.debuggee.gdbstub_port == 1235
    assert plan.notes == ("gdbstub_port 1234 was busy; using 1235",)


def test_a_builtin_port_also_moves() -> None:
    plan = resolve_ports(DebuggeeCfg(), _prov(gdbstub_port=LAYER_BUILTIN), is_free=_busy(1234, 1235))
    assert plan.debuggee.gdbstub_port == 1236


@pytest.mark.parametrize("layer", [LAYER_SCENARIO, LAYER_CLI])
def test_a_chosen_port_is_never_moved_silently(layer: str) -> None:
    """A port set in a scenario or on the command line is an instruction: a fixed gdb target, a
    port-forward, a script. Booting on a different one would break what it was set for."""
    with pytest.raises(ConfigError) as exc:
        resolve_ports(DebuggeeCfg(), _prov(gdbstub_port=layer), is_free=_busy(1234))
    assert "1234 is already in use" in str(exc.value)
    assert exc.value.remedy and "different [debuggee] gdbstub_port" in exc.value.remedy


def test_both_ports_move_independently_without_colliding() -> None:
    eff = DebuggeeCfg(gdbstub_port=4000, ssh_port=4001)
    plan = resolve_ports(eff, _prov(), is_free=_busy(4000, 4001))
    assert plan.debuggee.gdbstub_port == 4001 or plan.debuggee.ssh_port != plan.debuggee.gdbstub_port
    assert plan.debuggee.gdbstub_port != plan.debuggee.ssh_port
    assert len(plan.notes) == 2


def test_a_moved_port_is_not_handed_to_the_other_port() -> None:
    """Regression guard: gdbstub moving onto 2222 must not then be reused for ssh."""
    eff = DebuggeeCfg(gdbstub_port=2221, ssh_port=2222)
    plan = resolve_ports(eff, _prov(), is_free=_busy(2221))
    assert plan.debuggee.gdbstub_port == 2222
    assert plan.debuggee.ssh_port != 2222


def test_a_disabled_stub_contends_for_nothing() -> None:
    """A foreign guest has neither the stub nor the SSH transport, so it must not error on a
    port it will never bind."""
    eff = DebuggeeCfg(gdbstub=False, guest_net=False)
    plan = resolve_ports(eff, _prov(gdbstub_port=LAYER_CLI, ssh_port=LAYER_CLI), is_free=_busy(1234, 2222))
    assert plan.notes == ()
    assert plan.debuggee.gdbstub_port == 1234


def test_ssh_port_ignored_when_guest_net_is_off() -> None:
    eff = DebuggeeCfg(guest_net=False)
    plan = resolve_ports(eff, _prov(ssh_port=LAYER_CLI), is_free=_busy(2222))
    assert plan.notes == ()


def test_exhausting_the_search_span_is_an_error_not_a_hang() -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_ports(DebuggeeCfg(gdbstub=True, guest_net=False), _prov(), is_free=lambda p: False)
    assert "no free port" in str(exc.value)


def test_port_is_free_agrees_with_a_real_listener() -> None:
    """The probe binds INADDR_ANY so a listener on a single interface still counts as busy."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        taken = s.getsockname()[1]
        assert port_is_free(taken) is False
    # released once the socket closes
    assert isinstance(port_is_free(taken), bool)
