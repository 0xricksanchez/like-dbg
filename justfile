# LIKE-DBG developer commands
bootstrap:
    ./scripts/bootstrap.sh

check:
    uv run python -m likedbg.bootstrap --check

test:
    uv run pytest -q

lint:
    uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg
