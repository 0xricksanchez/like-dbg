# LIKE-DBG Rework — Roadmap & Handoff

**Purpose:** the single durable picture of what's done and what's left, so a fresh session
can continue the rework with one prompt. `dev` represents the FULL rewrite and stays **local
(never pushed)** until the whole rework is done; `main` is frozen at `3737ec3`.

> **Continue in a fresh session with:**
> *"Read docs/superpowers/ROADMAP.md and continue the like-dbg rework — pick the next
> unstarted item, brainstorm→spec→plan→subagent-driven-development (or systematic-debugging
> for bugs), and keep dev local."*

## Status (2026-06-25)

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

Next planned continuation: **§C cache niceties** (small), then choose the next large Sub-project B-E track.
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
- **`just build-images`** rebuilds all 4 images from the current dockerfiles (base→kbuilder,
  rootfs, debugger). Stale images silently break the pipeline (root cause of the rootfs bug).
- Runtime supports both macOS volume mode and Linux bind mode; the host profile decides storage,
  debuggee backend, network mode, and acceleration.
- tmux uses **`pane-base-index`** (this host = 1); `Session` queries it, never assume 0. The shipped
  workflow uses the named socket `tmux -L likedbg`; list/attach with that same `-L likedbg` socket.
- User has **uncommitted local edits in flight** (maintainer email `admin@`→`mail@` sweep;
  `.dockerfile_base` `ubuntu:24.04`→`26.04`; `ctf/misc/cpio.sh` reformat). Leave them unless
  asked; if rebuilding images they'll pick up `ubuntu:26.04`.
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

### C. Cache niceties (small)
- `--use` rootfs **build-if-absent** (currently requires a cached rootfs; spec §4.5 v1 note).
- `--list` build size: shows `-` for **bind** builds (B3 live-gate confirmed — `cli._artifact_size`
  looks for the volume-export path `artifacts/<label>/Image`; bind images live at
  `artifacts/ksrc/<label>/arch/<arch>/boot/<image>`); for volume it shows the host-export Image only.
  Fix: in bind stat `manifest.paths["image_host"]`; add the in-volume tree size for volume (container `du`).
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
