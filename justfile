# LIKE-DBG developer commands
bootstrap:
    ./scripts/bootstrap.sh

check:
    uv run python -m likedbg.bootstrap --check

test:
    uv run pytest -q

lint:
    uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg

# Builds in dependency order (base first; the others are FROM it). Skipping this after a
# source change leaves a STALE image in the pipeline (e.g. an old rootfs.sh that fails on
# virtiofs), which silently produces wrong/no artifacts.

# Rebuild all container images from current dockerfiles (run after editing a dockerfile/script)
build-images:
    uv run ./start_kgdb --build-images
