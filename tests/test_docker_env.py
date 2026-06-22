from likedbg.docker_env import resolve_docker_host


def test_explicit_docker_host_env_wins():
    h = resolve_docker_host(env={"DOCKER_HOST": "unix:///x.sock"}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///x.sock"


def test_falls_back_to_context_when_env_unset():
    h = resolve_docker_host(env={}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///ctx.sock"


def test_none_when_neither_available():
    h = resolve_docker_host(env={}, read_context_host=lambda: None)
    assert h is None
