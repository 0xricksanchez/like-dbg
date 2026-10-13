#!/usr/bin/env bash
# Idempotent host setup for LIKE-DBG. macOS: colima + qemu + binfmt + uv.
# Linux: docker + binfmt + uv. Re-running is safe.
set -euo pipefail

OS="$(uname -s)"
log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$1"; }

ensure_brew_pkg() { brew list "$1" >/dev/null 2>&1 || brew install "$1"; }

if [ "$OS" = "Darwin" ]; then
  command -v brew >/dev/null || {
    echo "Homebrew required: https://brew.sh"
    exit 1
  }
  ensure_brew_pkg colima
  ensure_brew_pkg qemu
  ensure_brew_pkg uv
  ensure_brew_pkg just
  if ! colima status 2>&1 | grep -qi running; then
    log "starting colima (vz, 4 CPU, 8GiB, 60GiB disk)"
    colima start --vm-type vz --cpu 4 --memory 8 --disk 60 --mount-type virtiofs
  fi
else
  command -v docker >/dev/null || {
    echo "Docker engine required"
    exit 1
  }
  command -v uv >/dev/null || {
    echo "Install uv: https://docs.astral.sh/uv/"
    exit 1
  }
fi

log "installing qemu binfmt handlers (for cross-arch rootfs/builds)"
docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null

log "syncing python deps"
uv sync

log "prerequisite check:"
uv run python -m likedbg.bootstrap --check || true
log "done. If anything shows MISSING above, follow its '->' remedy."
