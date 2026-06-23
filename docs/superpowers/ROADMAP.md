# LIKE-DBG Rework — Roadmap & Handoff

**Purpose:** the single durable picture of what's done and what's left, so a fresh session
can continue the rework with one prompt. `dev` represents the FULL rewrite and stays **local
(never pushed)** until the whole rework is done; `main` is frozen at `3737ec3`.

> **Continue in a fresh session with:**
> *"Read docs/superpowers/ROADMAP.md and continue the like-dbg rework — pick the next
> unstarted item, brainstorm→spec→plan→subagent-driven-development (or systematic-debugging
> for bugs), and keep dev local."*

## Status (2026-06-23)

M1 Sub-project A (Foundation) is complete and extended; all merged to `dev` (tip `a109fb5`).
Don't re-derive history — read these:
- Project state & decisions: the auto-loaded memory `project-like-dbg-revival.md`.
- Glossary: `CONTEXT.md`. Decisions: `docs/adr/0001..0003`.
- Specs: `docs/superpowers/specs/2026-06-22-like-dbg-foundation-revival-design.md` (vision
  + sub-projects A–E), `2026-06-23-build-reuse-cache-design.md` (§4.5 management CLI; §3/§4 v1 scope).
- Plans (all executed): `docs/superpowers/plans/2026-06-22-m1-*` (Plans 1–3),
  `2026-06-23-m1-plan4-one-command-ux.md`, `m1-plan5-build-cache.md`, `m1-plan6-cache-management.md`.
- Live transcripts: `docs/superpowers/notes/2026-06-23-*` (build-cache-live, cache-management-live, rootfs-build-fix).

**Daily-driver works on the M5 (arm64/macOS/colima, volume mode):** `uv run ./start_kgdb`
builds-or-reuses → native-HVF boot → gef/pwndbg at `start_kernel`; `--list`/`--clean`/`--use`/
`--adopt`/`--force-rebuild`; `ext = gef|pwndbg` selectable. Rebuild images after editing any
dockerfile/baked script with **`just build-images`**.

## Operational gotchas a fresh session MUST know
- **`dev` stays local — never `git push`.** Feature branch off `dev`, merge locally, delete.
- **`just build-images`** rebuilds all 4 images from the current dockerfiles (base→kbuilder,
  rootfs, debugger). Stale images silently break the pipeline (root cause of the rootfs bug).
- Runtime is **volume-mode only** — `cli.require_volume_mode` hard-errors on bind mode.
- tmux uses **`pane-base-index`** (this host = 1); `Session` queries it, never assume 0.
- User has **uncommitted local edits in flight** (maintainer email `admin@`→`mail@` sweep;
  `.dockerfile_base` `ubuntu:24.04`→`26.04`; `ctf/misc/cpio.sh` reformat). Leave them unless
  asked; if rebuilding images they'll pick up `ubuntu:26.04`.
- Cache lives in Docker volume `likedbg_ksrc` + host `artifacts/cache/{builds,rootfs}/`.
  Current entries: build `linux-6.6.30-35e79946`, rootfs `rootfs-arm64-bookworm-1c5f217c`.

## Remaining work

### A. Deferred polish (small; from Plan 5/6 reviews — NOT recorded elsewhere, capture here)
These were triaged "defer" during reviews. Good warm-up tasks; batch a few per branch.
- `cache.remove_cached` ignores `manifest.storage_mode` for builds (assumes volume) — guard or
  comment until bind runtime exists.
- Hardcoded image/volume literals duplicated (`"likedbg_ksrc"`, `"like_debugger:latest"`,
  `"like_kbuilder_arm64:latest"`, `"like_rootfs:latest"`) across `cli.build_pipeline`/
  `build_use_pipeline`/`cmd_use` and `cache`/`adopt`/`export` constants → extract shared constants.
- `adopt._parse_makefile_version` yields `"None.None.None"` on a malformed/missing Makefile →
  raise a clear `CacheError("could not parse kernel version …")`.
- `export.py` uses a literal `/ksrc` instead of the `_VOLUME_MOUNT` constant for `vmlinux_in_tree`.
- `cache.slug` has no docstring / no empty-string test; `list_manifests` could sort by `p.stem`.
- `write_manifest` uses a fixed `.json.tmp` temp name (benign under single-active-run).
- Stopped-container accumulation: stages/`remove_cached` `run_detached` without `auto_remove`
  (pre-existing project-wide; export/build/rootfs/adopt all leave stopped containers).

### B. Foundation completion (medium; finishes Sub-project A's stated scope)
- **x86_64-on-Mac end-to-end:** the CLI assembly is native-HVF-only today; wire the
  in-container TCG debuggee path (the `.dockerfile_dbge` debuggee image) + validate
  build→boot→debug for x86_64 on the Mac (ADR-0001 says x86_64-on-Mac stays in-container TCG).
- **Image-build lifecycle:** `ContainerService.build_image` exists but is only invoked via
  `just build-images`. Wire it into the package (a `--build-images`/`force_rebuild` path,
  and/or auto-build-if-missing) so image currency isn't a manual step.
- **bind/Linux runtime (un-gate `require_volume_mode`):** the cache architecture is already
  storage-mode-aware (`cache.locations`), but the live wiring is volume-only. Needs: thread
  `storage_mode` into `cli.run_gdb`'s `locations()` call (currently hardcoded `"volume"`);
  a host-readable Image path for the bind-mode Debuggee (Export is volume-only — "the build
  is the export" in bind); in-container QEMU launch (Linux `/dev/kvm`); then drop the guard.

### C. Cache niceties (small)
- `--use` rootfs **build-if-absent** (currently requires a cached rootfs; spec §4.5 v1 note).
- `--list` build size shows the host-export Image only; add the in-volume tree size (container `du`).
- `--adopt-rootfs` analogue (`--adopt` only migrates kernel builds; rootfs adoption was manual).

### D. Sub-projects B–E (large; see foundation spec §1 for the vision)
Each gets its own brainstorm→spec→grill→plan→subagent-driven cycle.
- **B — Modern debugging UX:** sanitizer profiles, symbolized panics, kernel-aware gdb/gef/
  pwndbg helpers (lx-/structs), QEMU snapshot/restore.
- **C — CTF / exploitation ergonomics:** cpio unpack/repack (`ctf/misc/cpio.sh`), vuln
  playgrounds (the bundled Pawnyable LK01 configs are a seed), exploit-dev conveniences.
- **D — Bug-finding / fuzzing:** real syzkaller integration, crash triage/dedup.
- **E — AI assistant pane:** a Claude-backed tmux pane observing QEMU/gdb output, offering live guidance.

## Workflow (use the same discipline that built Plans 4–6)
- Features: `superpowers:brainstorming` → write spec (`docs/superpowers/specs/`) →
  `grill-with-docs` (sharpen vs CONTEXT.md/ADRs) → `superpowers:writing-plans` →
  `superpowers:subagent-driven-development` (per-task implementer=haiku when the plan carries
  full code / sonnet for cli/integration; per-task review=sonnet; final whole-branch review=opus;
  one fix wave for must-fixes) → controller-driven live gate → `superpowers:finishing-a-development-branch`
  (merge to `dev` **locally**).
- Bugs: `superpowers:systematic-debugging` (root cause before fixes).
- Per-task ledger lives at `.git/sdd/progress.md` (local, ephemeral — promote anything durable here).

## Suggested skills for the next session
`superpowers:brainstorming`, `superpowers:writing-plans`, `superpowers:subagent-driven-development`,
`superpowers:systematic-debugging`, `grill-with-docs`, `superpowers:finishing-a-development-branch`,
`superpowers:test-driven-development`, `superpowers:verification-before-completion`.
