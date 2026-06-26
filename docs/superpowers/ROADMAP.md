# LIKE-DBG Rework — Roadmap & Handoff

**Purpose:** the single durable picture of what's done and what's left, so a fresh session
can continue the rework with one prompt. `dev` represents the FULL rewrite and stays **local
(never pushed)** until the whole rework is done; `main` is frozen at `3737ec3`.

> **Continue in a fresh session with:**
> *"Read docs/superpowers/ROADMAP.md and continue the like-dbg rework — pick the next
> unstarted item, brainstorm→spec→plan→subagent-driven-development (or systematic-debugging
> for bugs), and keep dev local."*

## Status (2026-06-26)

M1 Sub-project A (Foundation) is **complete** — §A, §B1, §B2, **and §B3 all merged to `dev`**.
§B (Foundation completion) is fully done. Landed 2026-06-24: **§B3 — un-gate the
bind/Linux runtime — DONE + LIVE-GATE PASSED on a real arm64 Ubuntu 26.04 VM for BOTH arches**
(x86_64 foreign-arch *and* arm64 native-arch: bind build→rootfs→in-container TCG boot→gdb at
start_kernel→systemd userspace; host-editable trees; auto→host + published topology; configurable
gdb_port). Earlier on `dev`: §A deferred-polish batch, §B1 image-build lifecycle, §B2 x86_64-on-Mac
in-container TCG (live-gate PASSED on the M5) + 3 ubuntu:26.04 build-chain fixes.

Post-B3 follow-ups landed on `dev`:
- **Observability/logging Plan 1** — stderr + per-run log files, streaming `ContainerService.exec`, rootfs
  log routing + one retry, per-stage timings, and default-visible cache-hit notices.
- **Process panes / tmux workflow Plan 2** — QEMU/GDB launch as tmux process panes instead of shell
  `send-keys`, pane-local `remain-on-exit`, `C-b B` Debuggee restart in the shipped `.tmux.conf`,
  `likedbg-reconnect`, README guidance for the dedicated `tmux -L likedbg` server, and ADR-0005.
- **Cache niceties + cleanup Plan 3** — `--use` rootfs build-if-absent, `--adopt-rootfs`,
  bind and volume-aware `--list` sizes, B1 image lifecycle live checks, helper-container cleanup,
  and deferred polish cleanup.
- **Rootfs build/runtime hardening** — `rootfs.sh` now logs phases, uses direct `mkfs.ext4 -d`
  image population, keeps SSH/build-essential/gcc/clang while dropping Plymouth, emits ed25519
  keys, conditionally registers host binfmt without resetting handlers, and no longer writes a
  guest `binfmt_misc` fstab mount that forced emergency mode. The generated guest fstab now uses
  the real virtio root device (`/dev/vda`, fsck pass `0`) so clean boots remount `/` read-write
  without stalling on image fsck. Rootfs cache keys now include the baked script hash and stale
  `like_rootfs:latest` images are rejected before
  rebuilds. QEMU also passes `net.ifnames=0` so the guest NIC remains `eth0`.

Next planned continuation: **Sub-project B — Modern debugging UX**. B1+B2 are implemented (2026-06-26);
the next slice is **B3** (crash/oops detector). Full B roadmap below.
See `docs/superpowers/specs/2026-06-25-modern-debugging-ux-b1-b2-design.md` for the B1+B2 spec.
Don't re-derive history — read these:
- Project state & decisions: the auto-loaded memory `project-like-dbg-revival.md`.
- Glossary: `CONTEXT.md`. Decisions: `docs/adr/0001..0003`.
- Specs: `docs/superpowers/specs/2026-06-22-like-dbg-foundation-revival-design.md` (vision
  + sub-projects A–E), `2026-06-23-build-reuse-cache-design.md` (§4.5 management CLI; §3/§4 v1 scope),
  `2026-06-24-logging-session-ergonomics-design.md` (observability + process panes).
- Plans (all executed): `docs/superpowers/plans/2026-06-22-m1-*` (Plans 1–3),
  `2026-06-23-m1-plan4-one-command-ux.md`, `m1-plan5-build-cache.md`,
  `m1-plan6-cache-management.md`, `2026-06-24-observability-logging.md`,
  `2026-06-24-process-panes.md`.
- Live transcripts: `docs/superpowers/notes/2026-06-23-*` (build-cache-live, cache-management-live, rootfs-build-fix).

**Daily-driver works on the M5 (arm64/macOS/colima, volume mode):** launch a project tmux server with
`tmux -L likedbg -f .tmux.conf new -s LIKE-DBG`, then run `uv run ./start_kgdb` inside it.
The command builds-or-reuses → native-HVF boot → gef/pwndbg at `start_kernel`; `C-b B` restarts the
Debuggee pane in place, then `likedbg-reconnect` in GDB reconnects to the new QEMU gdbstub and resumes
to `start_kernel`. From the Debugger container, raw manual attach uses
`target remote host.docker.internal:1234` — **not** localhost. `--list`/`--clean`/`--use`/`--adopt`/
`--force-rebuild`; `ext = gef|pwndbg` selectable. Rebuild images after editing any dockerfile/baked
script with **`just build-images`**.

## Operational gotchas a fresh session MUST know
- **`dev` stays local — never `git push`.** Feature branch off `dev`, merge locally, delete.
- **`just build-images`** rebuilds all 5 images from the current dockerfiles (base→kbuilder,
  rootfs, debugger, debuggee). The rootfs builder image is content-stamped with
  `io/scripts/rootfs.sh`; after editing that script, rebuild images before rebuilding rootfs.
- Runtime supports both macOS volume mode and Linux bind mode; the host profile decides storage,
  debuggee backend, network mode, and acceleration.
- tmux uses **`pane-base-index`** (this host = 1); `Session` queries it, never assume 0. The shipped
  workflow uses the named socket `tmux -L likedbg`; list/attach with that same `-L likedbg` socket.
- No known uncommitted local edits as of 2026-06-25 after the cache cleanup merge; still check
  `git status` before editing because this is a shared workspace.
- Cache lives in Docker volume `likedbg_ksrc` or host bind trees, plus
  `artifacts/cache/{builds,rootfs}/`.

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

**Runtime audit done (2026-06-25):** a deliberately broken helper command raised `ContainerError`
with the failed command, exit code, and emitted marker output. `docker ps -a` is empty after removing
three verified old LIKE-DBG image-build helper leftovers.
**Polish done (2026-06-25):** removed the inert `from __future__ import annotations` in
`constants.py`; added exact-value asserts for KBUILDER/ROOTFS/DEBUGGER; cleaned cache comments
to refer to `VOLUME_MOUNT`; moved remaining function-scope test imports to module scope.
**Smoke note (2026-06-25):** the cache-niceties smoke left no running containers.

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
  **Runtime check done (2026-06-25):** `uv run ./start_kgdb --build-images` rebuilt all 5 images
  and stamped `likedbg.input_sha`; a temporary content edit to `io/scripts/rootfs.sh` triggered the
  stale warning for `like_rootfs:latest`; removing `like_debugger:latest` triggered the missing-image
  auto-build path and restored the image with the expected label.
  **Polish done (2026-06-25):** `build_image` tests now assert path/rm/nocache/labels forwarding,
  including `labels=None`; `copy_sources` now treats only tokenized `--from` flags as multi-stage
  copies.
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
  Polish done (2026-06-25): `_GDB_ARCH` now raises a clear error for unsupported arch values, and
  empty in-container QEMU mount lists no longer introduce double spaces in the generated command.
- **B3 — bind/Linux runtime — ✅ DONE + LIVE-GATE PASSED (2026-06-24; merged to `dev`, commits
  `b276c2f..d537573`):** un-gated the bind storage runtime so the daily-driver runs on Linux.
  **Layout B** (bind-mount the parent `artifacts/ksrc/` host dir at `/ksrc`, mirroring the volume
  mount → container-side paths are mode-invariant, only the `-v` source differs) + `tree_mount_source`
  helper; new **Network mode** axis (`[debuggee] network = auto|host|published`; Linux→host net+localhost,
  macOS→published+host.docker.internal; `network=host` rejected on macOS) + configurable
  `[debuggee] gdb_port` (QEMU `-gdb tcp::PORT`, not `-s`); arm64 `-cpu host` under KVM (cortex-a72 under
  TCG); `--device /dev/kvm` passthrough (unit-tested-only — no KVM on the gate VM); root build +
  `chown -R uid:gid` (Linux+bind) for host-editable trees; bind `remove_cached` (host rmtree); deleted
  `require_volume_mode`. 187 tests; opus whole-branch review clean. CONTEXT.md gains `Network mode`; no
  new ADR (realizes ADR-0001/0002). Spec/plan: `docs/superpowers/{specs,plans}/2026-06-24-b3-bind-linux-runtime*`.
  **LIVE-GATE PASSED on a real arm64 Ubuntu 26.04 VM (Docker 29.6, no /dev/kvm → TCG) — BOTH arches:**
  x86_64 (foreign-arch amd64 rootfs) *and* arm64 (native rootfs) → bind build (tree on host at
  `artifacts/ksrc/<label>`, owned by the host user, editable w/o sudo) → in-container TCG boot → gdb
  `hbreak start_kernel` (source-level) → continue → systemd userspace root shell. Verified live: live
  QEMU argv `--network host` (auto) and `-p PORT:PORT` (published override), bind image path, `-gdb
  tcp::PORT` (incl. custom 4444), `--list`/`--clean` (bind rmtree), no leftover containers.
  **Follow-up done (2026-06-24): rootfs robustness + observability Plan 1** — the FIRST foreign-arch
  rootfs build failed once (non-reproducible first-run env transient; 3 later fresh builds OK). The gap is
  now closed: `RootfsStage` routes streamed rootfs container logs into loguru, retries once on
  image-not-produced, and failures point at `artifacts/logs/latest.log`. `ContainerService.exec` streams
  build/container output to DEBUG, stderr gets stage timings, and cache-hit branches now log default-visible
  reuse notices.

### C. Cache niceties (small) — landed 2026-06-25
- `--use` rootfs **build-if-absent** now uses the existing `RootfsStage`, so a cached kernel build can
  boot with the active rootfs even when that rootfs has not been cached yet.
- `--list` build size now stats `manifest.paths["image_host"]` for bind builds and uses Docker
  `du -sb` for volume-mode kernel trees when Docker is reachable, with the host-export Image fallback
  preserved if volume inspection is unavailable.
- `--adopt-rootfs [SOURCE]` now copies a manually created legacy rootfs image into the keyed rootfs
  cache and writes the rootfs manifest.

### D. Sub-project B: Modern debugging UX
**B1+B2 implemented (2026-06-26).** Unit suite green. Controller-driven live gates are Task 20
(not yet run). B3-B6 remain to be started.

- **Plan:** `docs/superpowers/plans/2026-06-26-modern-debugging-ux-b1-b2-plan.md`
- **Spec + grill decisions (§10):** `docs/superpowers/specs/2026-06-25-modern-debugging-ux-b1-b2-design.md`
- **ADR:** `docs/adr/0006-toml-configuration-and-debug-profiles.md`

Key grill decisions recorded in spec §10 and ADR Resolution (2026-06-26 grill):
- Whole-Settings provenance: `load_config -> ConfigResolution(settings, provenance)`.
- `native` resolves in `HostProfile.detect` → `host.target_arch`; symbolic `native` never reaches recipes.
- Profile runtime defaults at layer 4; effective result in `RunResolution.effective_debuggee`.
- `pwndbg` is the de facto default (`default.toml`); `gef` via `local.toml` override.
- Two-phase load (select profiles, then finalize with provenance).
- `-c` is name-or-path (`-c lk01` → `configs/scenarios/lk01.toml`).
- `custom_modules` deferred to B6; B1 keeps only the validated schema slot.

Full B slice:
- **B1 — Debug profiles + post-build verification — ✅ IMPLEMENTED (2026-06-26):** named profiles
  (`exploit-dev`, `hardened`, `crash-debug`, `kasan`, `ubsan`, `lockdep`, `kcov-lite`); each resolves
  to kconfig fragments, boot args, expected `.config` assertions, warnings, and runtime defaults.
  Verifies the built `.config` after fresh builds and cache hits. Legacy INI config replaced by TOML
  stack with provenance.
- **B2 — Run artifacts + QEMU/GDB transcript capture — ✅ IMPLEMENTED (2026-06-26):** creates
  `artifacts/runs/<run-id>/` for every interactive run, recording resolved settings, host profile,
  labels, profile resolution graph, QEMU/GDB commands, kernel `.config`/`System.map` references, and
  Debuggee/Debugger pane transcripts via `tmux pipe-pane`. Transcripts are operator-pane logs, not
  byte-perfect serial capture (small gap at each `C-b B` restart is expected).
- **B3 — Crash/oops detector + symbolized reports:** parse serial output for panics, oopses,
  KASAN/UBSAN, GP faults, arm64 aborts, and call traces; produce `crash.json` + `crash.md`.
- **B4 — LIKE-DBG GDB helper pack + breakpoint profiles:** first-class GDB Python commands layered on
  `likedbg-reconnect` for kernel/session info, mitigation state, module symbol loading, common exploit
  structures, and breakpoint groups.
- **B5 — Reset/snapshot controls:** QMP/HMP-backed stop/continue/reset controls, rootfs
  snapshot/overlay mode for repeatable exploit attempts.
- **B6 — Guest exploit deploy/run loop:** helper commands to copy/build/run exploit payloads in the
  guest, capture stdout/stderr, preserve crash artifacts, and wire out-of-tree `custom_modules`.

### E. Later large tracks — Sub-projects C–E
Each still gets its own brainstorm→spec→grill→plan→subagent-driven cycle after the relevant B foundation
is in place.
- **C — CTF / exploitation ergonomics:** cpio unpack/repack (`ctf/misc/cpio.sh`), vuln
  playgrounds (the bundled Pawnyable LK01 configs are a seed), exploit-dev conveniences.
- **D — Bug-finding / fuzzing:** real syzkaller integration, crash triage/dedup. Depends on B1/B3-style
  sanitizer profiles and structured crash artifacts.
- **E — AI assistant pane:** a Claude-backed tmux pane observing QEMU/gdb output, offering live guidance.
  Best started after B2 creates structured run artifacts and B3 creates crash summaries.

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
