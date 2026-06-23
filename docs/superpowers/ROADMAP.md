# LIKE-DBG Rework — Roadmap & Handoff

**Purpose:** the single durable picture of what's done and what's left, so a fresh session
can continue the rework with one prompt. `dev` represents the FULL rewrite and stays **local
(never pushed)** until the whole rework is done; `main` is frozen at `3737ec3`.

> **Continue in a fresh session with:**
> *"Read docs/superpowers/ROADMAP.md and continue the like-dbg rework — pick the next
> unstarted item, brainstorm→spec→plan→subagent-driven-development (or systematic-debugging
> for bugs), and keep dev local."*

## Status (2026-06-23)

M1 Sub-project A (Foundation) is complete and extended; all merged to `dev` (tip `4cde38d`).
Landed 2026-06-23: the §A deferred-polish batch (all 7 items), §B1 image-build lifecycle, and
§B2 x86_64-on-Mac in-container TCG — **live-gate PASSED on the M5** (x86_64 build→foreign-arch
rootfs→in-container TCG boot→gdb→systemd userspace), incl. 3 ubuntu:26.04 build-chain fixes that
also unblock the arm64 daily driver (see §B2). Next unstarted: **§B3** (un-gate bind/Linux runtime)
— least valuable to a macOS user and not fully live-gateable on a Mac — or move to Sub-projects
C–E. (Maintainer commits `a365bdc`/`4cde38d` (ubuntu:26.04 bump + shell-script whitespace) also on `dev`.)
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

### A. Deferred polish — ✅ DONE (2026-06-23; merged to `dev`, commits `ba748f3..7aadbfd`)
All seven Plan 5/6 deferred items cleared via branch `chore/section-a-hardening`
(brainstorm→spec→grill→writing-plans→subagent-driven TDD; opus final review = "ready to merge"):
- new `src/likedbg/constants.py` + migration of all callers (cli/cache/adopt/export/build/unpack
  **and** `launchers.py` — the 8th `/ksrc` site, found by the final whole-branch review);
- `ContainerService.run_detached` defaults `auto_remove=True` (utility containers stop accumulating);
- `cache.remove_cached` guards its **build branch** on `storage_mode != "volume"` (rootfs branch
  is storage-mode-independent, untouched);
- `adopt._parse_makefile_version` raises a clear `CacheError` on a malformed Makefile;
- cache cosmetics: `slug` docstring, explicit `list_manifests` sort by `p.stem`, `mkstemp`
  `write_manifest`. Added the `Storage mode` glossary term to `CONTEXT.md`.
- Spec: `docs/superpowers/specs/2026-06-23-section-a-hardening-design.md`;
  plan: `docs/superpowers/plans/2026-06-23-section-a-hardening.md`.

**Outstanding runtime check (M5, spec §5 — not yet run):** `uv run ./start_kgdb`, then confirm
`docker ps -a` shows no leftover `like_dbg_base`/`like_kbuilder_arm64`/`like_rootfs` helper
containers, and a deliberately-broken build still surfaces output via `ContainerError`.
**Deferred cosmetics (tiny, optional future pass):** inert `from __future__ import annotations`
in `constants.py`; exact-value asserts for KBUILDER/ROOTFS/DEBUGGER in `test_constants.py`;
`cache.py` comment still says `/ksrc` literally; a few function-scope test imports vs module-level.

### B. Foundation completion (medium; finishes Sub-project A's stated scope)
Decomposed (2026-06-23) into three independent pieces: **B1** image-build lifecycle (done),
**B2** x86_64-on-Mac TCG, **B3** un-gate bind/Linux. B2 builds the in-container launch seam
that B3 reuses, so B2 before B3; B3 can't be fully live-gated on a macOS host. **Key grounding:**
`host_profile.detect` ALREADY resolves every case (`debuggee_mode` in-container/native-host,
`accel` hvf/kvm/tcg, `storage_mode`) and `DebuggeeStage` takes an injected `launch` callable —
so B2/B3 are downstream WIRING (a `qemu_container_command` + gdbstub networking, storage_mode
threading), not detection.
- **B1 — Image-build lifecycle — ✅ DONE (2026-06-23; merged to `dev`, commits `fc679eb..ee61257`):**
  new `src/likedbg/images.py` (`IMAGES` manifest + `input_sha` content hash over declared
  `build_inputs` + `build_images`/`ensure_current`), `ContainerService.build_image(labels=)` +
  `image_labels`, `--build-images` CLI dispatch + auto-build-missing/stale-WARN on the run +
  `--use` paths (subset per path), justfile delegates to the package. ADR-0004 (image currency)
  + `Container image` glossary term. 156 tests; opus whole-branch review clean. Spec/plan:
  `docs/superpowers/{specs,plans}/2026-06-23-b1-image-lifecycle*`.
  **Outstanding runtime check (M5, spec §5 — not yet run):** `uv run ./start_kgdb --build-images`
  builds 4 + stamps `likedbg.input_sha`; touch `io/scripts/rootfs.sh` → stale WARN fires;
  `docker rmi like_debugger:latest` → auto-build on next run.
  **Deferred minors (future pass):** `build_image` test under-asserts (no rm/nocache/path or
  `labels=None` checks); `copy_sources` `--from` substring vs token-anchored check.
- **B2 — x86_64-on-Mac (in-container TCG) — ✅ DONE + LIVE-GATE PASSED (2026-06-23; on `dev`,
  mechanism `6131a1a..dcbe133`, 26.04 fixes `3c562c5..324a719`):** debuggee image
  (`like_debuggee:latest`) in `images.IMAGES` + mode-aware `images.required_for(host)`;
  `qemu_container_command` launcher (publish-to-host `-p 1234:1234`; kernel `:ro`, **rootfs `:rw`**);
  `DebuggeeStage` owns the native-vs-in-container dispatch on `host.debuggee_mode`; arch-aware gdb
  (`i386:x86-64`); OS-based `gdbstub_addr` (realizes ADR-0001). 164 tests; opus whole-branch review
  clean. `Debuggee mode` glossary term; no new ADR. Spec/plan: `…/2026-06-23-b2-x86_64-mac*`.
  **LIVE GATE PASSED on the M5 (verify skill):** x86_64 build → **foreign-arch amd64 rootfs** →
  in-container TCG boot → containerized gdb `hbreak start_kernel` (source-level, `init/main.c:879`)
  → `continue` → **systemd userspace** (`Debian GNU/Linux 12 LIKE-DBG login:`) → runtime
  `break schedule` hit on the live kernel; no leftover containers (`--rm`/`auto_remove`).
  **3 ubuntu:26.04 build-chain bugs found + fixed (systematic-debugging) — also unblock the arm64
  daily driver:** (1) `3c562c5` rootfs image — 26.04 dropped `qemu-user-static` → install
  `qemu-user-binfmt` + `-static` hardlinks; (2) `62558e7` kernel build — clang-21 `-Werror` vs
  kernel 6.6.30 → `# CONFIG_WERROR is not set` in `generic.config`; (3) `324a719` in-container QEMU —
  rootfs disk must be `:rw` (was `:ro`). Observation: the build cache is fragment-**comment**-sensitive
  (ADR-0003 hashes file content), so doc-only fragment edits force a kernel rebuild.
  Deferred minors: `_GDB_ARCH` unguarded (unreachable via the arch Literal); empty-mounts double-space (unreachable).
- **B3 — bind/Linux runtime (un-gate `require_volume_mode`):** the cache architecture is already
  storage-mode-aware (`cache.locations`), but the live wiring is volume-only. Needs: thread
  `storage_mode` into `cli.run_gdb`'s `locations()` call (currently hardcoded `"volume"`);
  a host-readable Image path for the bind-mode Debuggee (Export is volume-only — "the build
  is the export" in bind); in-container QEMU launch (Linux `/dev/kvm`, reusing B2's launcher);
  then drop the guard.

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
