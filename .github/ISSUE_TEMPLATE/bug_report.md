---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is, and what you expected instead.

**To reproduce**
1. The exact command you ran (e.g. `uv run ./start_kgdb -c my-scenario --profile kasan`).
2. Whether it was a self-built kernel, a `[foreign]` / CTF kernel, or both.
3. The relevant parts of your TOML config — the scenario, `configs/local.toml`, or the profile.
   `uv run ./start_kgdb --explain-config` prints the fully resolved settings and which layer won
   each key, which is usually the fastest thing to paste.

**Output**
The error message or log output; `--verbose` logs every stage. If the guest booted, the run
directory under `artifacts/runs/<run-id>/` holds the resolved settings, the exact QEMU and GDB
commands, and the console log.

**Environment**
1. LIKE-DBG version (`uv run ./start_kgdb --version`), and the commit if you are on a branch.
2. Operating system and architecture (`uname -a`, or `cat /etc/os-release` on Linux).
3. Docker engine and version (`docker version`) — on macOS, say whether that is Docker Desktop,
   colima, or OrbStack.
4. Python and uv versions (`uv run python --version`, `uv --version`).
5. tmux version (`tmux -V`).

If the failure happens before anything boots, `just check` (or
`uv run python -m likedbg.bootstrap --check`) reports the host prerequisites and is worth pasting.

**Additional context**
Anything else that helps — screenshots, a minimal reproducer, whether it used to work.

Please remove credentials, private images, and challenge files before posting.
