import pytest

from likedbg.docker_env import daemon_remedy
from likedbg.docker_env import make_client
from likedbg.docker_env import resolve_docker_host
from likedbg.errors import ContainerError


def test_explicit_docker_host_env_wins():
    h = resolve_docker_host(env={"DOCKER_HOST": "unix:///x.sock"}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///x.sock"


def test_falls_back_to_context_when_env_unset():
    h = resolve_docker_host(env={}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///ctx.sock"


def test_none_when_neither_available():
    h = resolve_docker_host(env={}, read_context_host=lambda: None)
    assert h is None


def test_unreachable_daemon_is_a_typed_error_not_a_traceback():
    """Docker not running is the likeliest first-run failure; it used to escape as a 25-line
    docker.errors.DockerException traceback out of the middle of main()."""
    with pytest.raises(ContainerError) as exc:
        make_client("unix:///nonexistent/likedbg-test.sock")
    assert "docker" in str(exc.value).lower()
    assert exc.value.remedy
    # The endpoint is half the diagnosis: a stale DOCKER_HOST or docker context looks identical to
    # a stopped daemon until you can see which socket was tried.
    assert "unix:///nonexistent/likedbg-test.sock" in exc.value.message


def test_daemon_remedy_names_the_engines_that_host_actually_has():
    # macOS has no host dockerd: the fix is starting a VM-backed engine, and colima is not the only one.
    assert "Docker Desktop" in daemon_remedy("darwin")
    assert "colima" in daemon_remedy("darwin")
    assert "colima" not in daemon_remedy("linux")
    assert "docker" in daemon_remedy("linux").lower()
