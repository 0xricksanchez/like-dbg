# Changelog

<!--toc:start-->
- [Changelog](#changelog)
  - [[Unreleased]](#unreleased)
  - [[1.0.0] — 2026-07-28](#100-2026-07-28)
    - [Highlights](#highlights)
    - [Added](#added)
    - [Changed](#changed)
    - [Removed](#removed)
<!--toc:end-->

All notable changes to LIKE-DBG are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-07-28

A ground-up rewrite. Nothing carries over from `v0.1.1`: the configuration format, the CLI, the
module layout, and the Python floor all changed. The shape of the tool is the same — build or adopt
a kernel, boot it under QEMU, attach GDB, all in containers — but everything under it was rebuilt
around a cache and a stage pipeline.

If you are coming from `v0.1.x`, treat this as a new tool. Your `configs/*.ini` files do not
migrate; see [docs/configuration.md](docs/configuration.md) for the TOML equivalents.

### Highlights

- **Kernel builds are cached and never rebuilt for a configuration you already have.** A build is
  identified by the configuration you *requested* — version, arch, compiler, kconfig fragments,
  patch dirs — not by toolchain identity, so an image rebuild does not invalidate your kernels.
  Inspect and manage them with `--list`, `--use <label>`, `--clean` and `--prune`.
- **One kernel source tree, many configs.** Sources are shared and refcounted; each configuration
  builds out-of-tree into its own `O=` objdir, with ccache on top. Building a second
  profile of the same version does not re-download or re-unpack anything.
- **Configuration is TOML with full provenance.** Six layers — built-in, project default, profile
  runtime defaults, local, scenario, CLI — merge with the winning layer recorded per key, and
  `--explain-config` prints the result without touching Docker or tmux.
- **Debug profiles** turn an intent into kconfig fragments, post-build `.config` assertions, boot
  arguments, and runtime defaults. Seven ship: `exploit-dev`, `hardened`, `crash-debug`, `kasan`,
  `ubsan`, `lockdep`, and `kcov-lite`. A runtime toggle the built kernel cannot support is an
  error, not a silent no-op.
- **Crash intelligence.** The guest's serial output is captured byte-exact and separately from the
  operator's pane, then parsed into a structured report — panics, oopses, KASAN/UBSAN/WARN, call
  traces on both x86_64 and arm64 — rendered as `crash.json` + `crash.md` and enriched with GDB's
  live state at the fault. Re-runnable offline with `--analyze-crash`.
- **An exploit-dev inner loop.** `--run` compiles your `.c` static-musl for the guest arch,
  delivers it (in place via the 9p share, else over SSH), runs it, captures output into the run
  artifact, and chains straight into crash analysis. The compile toolchain is a
  container; nothing lands on your host.
- **Custom kernel modules** build out-of-tree against the running session's kernel and load on
  command with `--insmod` / `--rmmod` — never at boot, so GDB can be armed before the module's
  `init` runs.
- **CTF and foreign kernels boot verbatim.** Point a `[foreign]` scenario at a challenge's
  `bzImage`/`Image` and it adopts it without a build: arch auto-detected from the ELF, the
  challenge's own command line preserved, and kernel symbols recovered from the image's kallsyms
  when no `vmlinux` ships with it. Exploits are delivered by initramfs repack
  or live console upload, and the challenge's own initramfs scripts are never rewritten.
- **Every run leaves an artifact.** `artifacts/runs/<run-id>/` holds the requested and effective
  settings, profile resolution, the exact QEMU and GDB commands, the console log, pane transcripts,
  `.config` snapshots, and a status — including for runs that failed verification before boot.
- **Debug two things at once.** Each boot takes its own tmux session, named after what it is
  debugging (`LIKE-DBG-pawnyable-lk01`, `LIKE-DBG-6_6_30-kasan`), picks host ports nobody else is
  holding, and answers `--run`/`--insmod`/`--rmmod` for *its* guest rather than whichever booted
  most recently. Each session's guest writes to its own copy-on-write overlay, so guest state
  survives `--re-run` while the shared rootfs image stays pristine -- a guest can no longer
  degrade the cached image for every later run.
- **macOS and Linux are both first-class.** QEMU runs as a host process where hardware acceleration
  is available and in-container otherwise; the kernel tree lives in a named volume or a host bind
  depending on the filesystem's case sensitivity. Both are detected, not configured.

### Added

**Kernel builds and the build cache**

- Content-addressed build cache with human-readable labels, atomic manifests, and a typed registry.
- Shared source trees with refcounting; orphaned sources are dropped automatically.
- Out-of-tree per-config builds (`O=`) with a persistent, capped ccache volume.
- Opt-in LRU eviction with a size cap (`[cache] max_size`), `--prune [SIZE]`, and an auto-sweep at
  a 90% low-water mark; the latest run's build is protected.
- `--list` shows builds, rootfs images, and shared sources in an aligned table, with sizes in the
  same units the config accepts (`3.0G`, not `3221225472`) and last-used times.
- Kconfig fragment library plus `[build] extra_fragments` and ordered `patch_dirs`.
- Toolchain registry: clang/LLVM as the universal cross-compiler default, gcc opt-in per arch.

**Configuration and profiles**

- Pydantic-typed TOML settings with a six-layer loader and per-key provenance. Unknown or misplaced
  keys are rejected by name, so a typo or a key that moved is a one-line fix.
- Scenario files, a `local.toml` overlay, and a profile registry shipped under `configs/`.
- `--explain-config [text|json]` — a Docker-free, tmux-free dry run of the resolved settings.
- Profile verification as a pipeline stage: post-build `.config` assertions with arch and
  kernel-version selectors, failing the run before boot rather than after.

**Debugging**

- Both GEF and pwndbg are installed; `[debugger] ext` selects per run, defaulting to pwndbg.
- A three-pane tmux layout (Debuggee, Debugger, host) driven as process panes, not interactive
  shells, so a crashed pane is a signal rather than a dead prompt.
- `break_on_crash`, configurable fatal `crash_breakpoints`, and separately gated
  `sanitizer_breakpoints` armed behind a one-shot userspace breakpoint.
- GDB-native debuginfod, resolved automatically per run type.
- `--restart-debuggee` and `--re-run` rebuild the session without losing the host pane.
- One tmux session per boot, named for the scenario, the cached build, or the kernel and profile,
  so a still-running session no longer blocks the next one.
- Host ports are checked before use. A port you never set (the shipped default) moves out of the
  way and says so; one you set in a scenario, `local.toml`, a profile or on the CLI is honoured
  exactly or reported busy -- never changed underneath you.
- Each session boots a qcow2 overlay over the shared rootfs image, so concurrent guests no longer
  contend for QEMU's write lock on it.

**Exploit development**

- SSH control transport over user-mode networking plus a 9p live share mounted at `/mnt/exploit`,
  so guest output survives a panic.
- `--run` / `--upload` with static-musl cross-compilation for either guest arch, an `[exploit]
  flags` knob, and a persistent zig cache volume for warm compiles.
- `--insmod` / `--rmmod` with build-if-stale and force-unload.

**Foreign and CTF kernels**

- `[foreign]` scenarios: adopt an image, optional `vmlinux` and `initramfs`, a verbatim command
  line, and extra QEMU arguments.
- Kernel-symbol recovery from a bzImage's kallsyms when no `vmlinux` is supplied, with an explicit
  trust gate and a decompress-only fallback.
- Exploit delivery by initramfs repack, or live base64 console upload with no reboot.
- An outbound SLIRP NIC by default, with the interface name matched host-side so the challenge's
  own `ifup` wait succeeds — never by editing the initramfs.
- Repacks are Stamp-guarded: an unchanged exploit reuses the previous repack instead of paying the
  container round trip, and says so in the log.
- A Pawnyable LK01 scenario and walkthrough ship as a worked example.

**Observability and safety**

- Run artifacts with status transitions, including `profile-verification-failed` and `launch-failed`.
- A typed error hierarchy where every failure carries an actionable remedy.
- Container-image currency by content hash of declared build inputs, warning rather than silently
  rebuilding.
- `bootstrap --check` reports host prerequisites with remedies, and reports what it cannot verify
  as unknown rather than guessing.
- `--help` describes every flag, grouped by what it is for (launching, driving a live session,
  inspecting, maintenance), and `--version` reports the release.
- Failures carry remedies rather than tracebacks: malformed TOML names its own line and column, an
  unknown or misplaced config key is named, a half-written run artifact is reported as such,
  running outside a LIKE-DBG checkout says so instead of naming a dockerfile, an unreachable
  Docker daemon names the endpoint it tried plus how to start an engine on this host, and a launch
  attempted outside tmux prints the exact command that starts the project's tmux server.
- `Ctrl-C` out of a long build exits quietly with status 130 instead of a `KeyboardInterrupt`
  traceback; Stamps and Manifests are written only after their output verifies, so the interrupted
  stage is redone rather than reused.
- `--explain-config` judges a `[foreign]` scenario the way the run does -- adopting the kernel's
  architecture and skipping build-time `.config` gates -- so the dry run and the real boot agree.

### Changed

- **Breaking: configuration moved from INI to TOML.** `configs/system.ini` and `configs/user.ini`
  are replaced by `configs/default.toml`, `configs/local.toml`, scenarios, and profiles.
- **Breaking: the entry point is `uv run ./start_kgdb`**, not `python start_kgdb.py`.
- **Breaking: Python 3.12 or newer** is required (was 3.10).
- **Breaking: the package is `src/likedbg/`**, replacing the flat `src/*.py` modules. Anything
  importing `src.debuggee`, `src.kernel_builder`, and friends will not work.
- `--force-rebuild` applies to the command you type it on, not the session: it no longer sticks to
  every later `--re-run`, and `--re-run --force-rebuild` now works (it used to be ignored). On a
  `[foreign]` scenario it reaches both the extracted vmlinux and the repacked initramfs.
- Dependency management moved from poetry to uv, with a locked `uv.lock`.
- Tooling moved from black and flake8 to ruff (lint plus format) and mypy, all enforced in CI
  alongside pytest with coverage.

### Removed

- The `fabric` SSH dependency, replaced by a small injectable ssh/scp seam.
- The `.ini` loader (`cfg_setter`) and the legacy per-module configuration blocks.

[1.0.0]: https://github.com/0xricksanchez/like-dbg/compare/v0.1.1...v1.0.0
