# M1 Plan 6 — Build Cache Management: live verification (2026-06-23)

Host: Apple Silicon macOS, colima, volume mode. Existing cache: adopted build
`linux-6.6.30-35e79946` + seeded rootfs `rootfs-arm64-bookworm-1c5f217c`.

## Result: PASS — `--list`, `--use`, `--clean` all work

### `--list` (Docker-free)
```
kind    label                            version  arch   size        created
build   linux-6.6.30-35e79946            6.6.30   arm64  34669056    2026-06-23
rootfs  rootfs-arm64-bookworm-1c5f217c   -        arm64  3221225472  2026-06-23
```
Reads host manifests only — no colima/tmux needed. Build size shown is the host-export
Image (the in-volume tree size is a future enhancement; see plan note).

### `--use linux-6.6.30-35e79946` (inside tmux)
- pane 1 pipeline ran **launch-only**: `export → debuggee → debugger` (no download/unpack/
  build/rootfs) — zero rebuild.
- pane 2: native HVF QEMU booted the cached kernel.
- pane 3: `gef➤`, stopped at `start_kernel` (BREAKPOINT), bt `start_kernel ← __primary_switched`.
- Arch precedence: settings reloaded with the manifest's arch override; `ext` from active config.

### `--clean` round-trip
- Created a throwaway build manifest `linux-0.0.0-deadbeef`; `--list` showed it.
- `--clean linux-0.0.0-deadbeef` → `removed build linux-0.0.0-deadbeef` (exercised the container
  `rm -rf /ksrc/<label>` path; harmless on the non-existent dir).
- `--list` after: throwaway gone, the real build + rootfs **intact**.
- `--clean nope-not-real` → `CacheError: no cached artifact labelled 'nope-not-real' → fix: run start_kgdb --list`.

## Deferred (v1 scope / follow-ups)
- `--use` requires the rootfs to be already cached (no build-if-absent) — depends on the
  rootfs.sh fresh-build fix (tackled next).
- `--list` build size is the host-export Image, not the in-volume tree (would need a container `du`).
- `--use`/`--clean` currently run `resolve_version`/recipe construction before dispatch (can fail on
  network/config before checking the cache) — guard candidate for the final-review fix wave.
