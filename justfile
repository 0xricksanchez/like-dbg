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
    docker build -f .dockerfile_base     -t like_dbg_base:latest        --build-arg USER=user .
    docker build -f .dockerfile_kbuilder -t like_kbuilder_arm64:latest  --build-arg USER=user .
    docker build -f .dockerfile_rootfs   -t like_rootfs:latest          --build-arg USER=user .
    docker build -f .dockerfile_dbg      -t like_debugger:latest        --build-arg USER=user .
