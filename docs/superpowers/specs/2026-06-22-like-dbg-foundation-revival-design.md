# LIKE-DBG Revival — Sub-project A: Foundation (cross-platform revival, modern toolchain, native aarch64, architecture overhaul)

- **Date:** 2026-06-22
- **Status:** Approved design, pending implementation plan
- **Author:** 0x434b (with Claude)

## 1. Context

LIKE-DBG is a fully dockerized Linux kernel debugging environment: a staged Python
pipeline (download → unpack → build kernel → build rootfs → QEMU debuggee → gdb+GEF/pwndbg
debugger) orchestrated into a tmux session. It went effectively unmaintained after ~Sept
2023 (only dependabot bumps since). The goal now is to revive it as the daily-driver
tooling for a Linux kernel exploitation deep-dive (bugs + blog posts).

The full vision spans five subsystems and is **decomposed** into sequential sub-projects,
each with its own spec → plan → implementation cycle:

- **A — Foundation** (this spec): cross-platform revival + modern toolchain + native
  aarch64 + internal architecture overhaul. *The unblocker for everything else.*
- **B — Modern debugging UX** (depends on A): sanitizer profiles, symbolized panics,
  kernel-aware gdb/gef/pwndbg helpers, QEMU snapshot/restore.
- **C — CTF / exploitation ergonomics** (depends on A): cpio unpack/repack, vuln
  playgrounds, exploit-dev conveniences.
- **D — Bug-finding / fuzzing** (depends on A + B): real syzkaller integration, crash
  triage/dedup.
- **E — AI assistant pane** (depends on A): a Claude-backed tmux pane that observes the
  QEMU/gdb output and offers live guidance.

This spec covers **Sub-project A only**. B–E are out of scope here.

## 2. Target environment & constraints

- Primary host: **Apple M5 Pro, arm64, macOS 26.4.1** (Apple Silicon). Currently has the
  Docker CLI but **no running engine**, and **no QEMU, colima/lima/OrbStack, or poetry**.
- Must run on **macOS and Linux alike**. Mac performance trade-offs are acceptable in
  principle, **but arm64 on the Mac must be fast by default**.
- **aarch64 is a first-class target** for both building and debugging; it is the primary
  fast native target. x86_64 is the correctness/compat target (TCG on the Mac; KVM on a
  Linux/x86 host).

## 3. Decisions (locked during brainstorming)

| Topic | Decision |
|---|---|
| Toolchain versioning | Pluggable/version-selectable design; **modern-first** implementation (≥6.6 LTS + mainline). |
| Rust-for-Linux | Toolchain-**ready, off by default** (rustup + pinned rustc + bindgen in image). |
| Container runtime | **colima** documented default; code stays runtime-agnostic over the Docker socket. |
| Rework depth | **Level 3 full overhaul** of internals (typed config, pipeline, session module, mypy). |
| Execution topology | **Native-accel where the OS requires it**: Linux = in-container QEMU + `/dev/kvm`; macOS = native QEMU + HVF; fallback TCG. |
| Compiler default | **clang/LLVM as universal cross-compiler**; GCC opt-in. |
| Kernel config | **kconfig fragments** merged via `merge_config.sh` (replaces `-e/-d` flag strings). |
| Networking | **Published ports + `host.docker.internal`** (drops `--net=host` + PID-namespace sharing). |
| Package manager | **uv** (replaces Poetry). |
| Python version | **3.12**. |
| Formatter | **ruff format** (drops black). |
| Logging | Keep **loguru**. |

## 4. Architecture

### 4.1 Pipeline shape (preserved) + the host-capability seam (new)

The six-stage pipeline and the tmux 3-pane UX are preserved. The one new central concept
is a **host-capability layer**: every platform-sensitive decision flows through a single
`HostProfile` built once at startup, instead of scattered, implicitly-Linux assumptions.

```
download → unpack → build → rootfs → debuggee → debugger
                     │        │         │           │
                     └────────┴─────────┴───────────┘
                         all consult HostProfile
```

`HostProfile` (`src/platform.py`, NEW) detects and exposes:
- OS (`linux`/`darwin`) and host arch (`arm64` on the M5).
- Container runtime (colima / Docker Desktop / OrbStack / native) via the Docker socket.
- **Accel capability** resolved to `kvm` / `hvf` / `tcg`: reachable `/dev/kvm` → `kvm`;
  else macOS + native QEMU present → `hvf`; else → `tcg`.
- **Debuggee execution mode**: `in-container` (Linux) vs `native-host` (macOS/HVF).
- **gdbstub/ssh addresses** the debugger should dial (`localhost`/shared-net vs
  `host.docker.internal`).

### 4.2 Core internal model (Level 3 overhaul)

Dataflow becomes: `INI → Settings (validated) → PipelineContext → Stages (via
ContainerService + Session), errors as exceptions`. Linear, typed, testable.

1. **Typed config (Pydantic v2), INI stays the UX.** The two INI files + `-c custom.ini`
   + CLI flags are unchanged for the user. An INI→Pydantic adapter parses them into one
   immutable, validated `Settings` tree (`GeneralCfg`, `KernelDlCfg`, `KernelBuilderCfg`,
   `RootfsCfg`, `DebuggeeCfg`, `DebuggerCfg`). Precedence: `system.ini` ◁ `user.ini` ◁
   `-c custom.ini` ◁ CLI flags. Invalid `arch`/`mode`/`accel`/version values are rejected
   **at startup with a clear message**. Replaces `cfg_setter`'s dynamic `setattr`.
2. **`PipelineContext`** — one typed object threaded through stages, carrying `Settings` +
   `HostProfile` and accumulating results (`kernel_root`, build status, rootfs path, image
   tags, CTF paths). Replaces dict-merging (`generic_args | kunpacker | dbge_args`).
3. **Explicit stage pipeline (plugin seam).** A `Stage` protocol — `run(ctx) -> ctx`,
   `should_skip(ctx)` — with concrete `Download / Unpack / Build / Rootfs / Debuggee /
   Debugger` stages. A `Pipeline` runner composes them and expresses the existing modes
   declaratively: partial runs (`-p N` = prefix), CTF mode (skip download/unpack/build +
   inject CTF paths), update-containers. Future sub-projects insert a stage instead of
   rewiring `main()`.
4. **`Session` module** owns tmux: `create()`, `split_for_debuggee()`,
   `split_for_debugger()`, `kill()`. Stages request panes; never call raw tmux. Also the
   clean insertion point for Sub-project E's AI pane.
5. **`ContainerService` (composition over inheritance).** Replaces the `DockerRunner`
   base-class that stages currently inherit. A runtime-agnostic service (build image, run,
   **`exec`**, stop) injected into stages. SSH/fabric is removed in favor of `exec_run`.
6. **Typed errors + mypy.** A `LikeDbgError` hierarchy (`ConfigError`, `DownloadError`,
   `BuildError`, `HostCapabilityError`, …) replaces scattered `exit(-1)`; one top-level
   handler in `main()` logs + sets the exit code. CI gains a `mypy --strict` gate.

### 4.3 Build & toolchain layer

- **Base image:** retire `ubuntu:22.04` → modern base (Ubuntu 24.04 / Debian trixie class)
  with current gcc (13/14), clang/LLVM (18+), `libelf`, `bc`, `flex`, `bison`, `cpio`,
  rustup-ready.
- **Compiler strategy:** **clang/LLVM as the universal cross-compiler** (`ARCH=… LLVM=1`
  builds every target from the arm64 host; no per-arch GCC cross packages). GCC available
  as opt-in. A `toolchain` config key (`clang-18`, `gcc-14`, `auto`) drives a small
  **toolchain registry** → `(packages, CC/LLVM/CROSS_COMPILE/ARCH env)`. Modern-first:
  wire + test current clang + gcc; the registry is the seam for pinned older toolchains.
- **Config fragments:** replace long `-e X -d Y` strings with composable **kconfig
  fragments** (`configs/fragments/debug.config`, `no-kaslr.config`, `syzkaller.config`,
  later `kasan.config`) merged with `scripts/kconfig/merge_config.sh` on top of
  `defconfig`. The `mode = generic|syzkaller|custom|config` UX selects fragment sets.
- **Build flow via `ContainerService.exec`** (no SSH): mrproper → apply patches →
  `defconfig` → merge fragments → `make -j$(nproc)` → modules → emit `vmlinux` +
  `Image`/`bzImage` + modules. **ccache/sccache on a persistent volume** for fast rebuilds.
- **Rust-ready, off by default:** rustup + pinned rustc + bindgen baked in; gated by
  `rust = no`; honored only when a target needs it.

### 4.4 Execution topology: debuggee, debugger & acceleration

- **Debuggee — two backends, one interface**, via a factory keyed on
  `HostProfile.debuggee_mode`:
  - `InContainerQemu` (Linux): `qemu-system-<arch>` in the debuggee container, `/dev/kvm`
    passthrough when accel is `kvm`.
  - `NativeQemu` (macOS): `qemu-system-aarch64 -accel hvf -cpu host` on the host, reading
    kernel `Image` + rootfs from the host filesystem (dockerized build bind-mounts
    artifacts out).
  - Both use a **typed QEMU command builder** emitting an **argv list, not a shell
    string** (safer, unit-testable). Per-arch machine/cpu (`arm64 → -M virt -cpu host`;
    `x86_64 → -cpu qemu64,+smep,+smap`), mitigation flags (kaslr/smep/smap/kpti/panic) from
    typed config, accel from `HostProfile`, gdbstub via `-S -s`. Rootfs-type inference
    (cpio→`-initrd`, ext4→`-drive`, qcow→`-drive`) preserved, typed.
- **Debugger — TCP attach, no namespace hacks.** gdb (containerized) attaches to the
  gdbstub **over TCP** at an address from `HostProfile` (`localhost`/shared-net on Linux;
  `host.docker.internal:1234` on macOS). Drops `--pid=container:like_debuggee` +
  `--net=host`. Fixes the `gef-remote` invocation to the correct kernel-remote form
  (today's `--qemu-user` is userland mode); keeps pwndbg `target remote`; auto-loads
  `vmlinux` + `lx-`/`vmlinux-gdb.py`; preserves the `gdb_script` user hook; keeps CTF
  vmlinux-extraction.
- **Networking contract (centralized).** Publish gdbstub `:1234` + guest SSH `:10021`,
  resolved through `HostProfile` (`gdbstub_addr`, `ssh_addr`). Linux via localhost/shared
  docker network; macOS via `host.docker.internal`.

### 4.5 Host bootstrap & tooling

- **One-command bootstrap** (justfile/Make target + thin script), idempotent and
  platform-aware:
  - macOS: `brew install colima qemu`, start colima with sane CPU/RAM, install Python +
    deps (uv), verify HVF.
  - Linux: verify Docker + `/dev/kvm` access (kvm group), install Python + deps (uv).
- **Tooling:** uv (PEP 621 `pyproject.toml` + `uv.lock`); Python 3.12; ruff for lint +
  format (drop black); `mypy --strict`; pre-commit hooks (ruff, mypy); Pydantic v2; keep
  loguru. CI: consolidate the four workflows, add mypy + a **build-and-boot smoke job**
  (incl. a macOS-arm64 runner for the native-HVF path).

## 5. Module-level change map

| Module | Change |
|---|---|
| `src/platform.py` | **NEW** — capability detection + `HostProfile`. |
| `src/config.py` | **NEW** — Pydantic schema + INI/CLI adapter; replaces `cfg_setter`. |
| `src/pipeline.py` | **NEW** — `Stage` protocol, `PipelineContext`, `Pipeline` runner. |
| `src/session.py` | **NEW** — tmux/session abstraction. |
| `src/container.py` | **NEW** — `ContainerService` (build/run/exec/stop), runtime-agnostic. |
| `src/errors.py` | **NEW** — `LikeDbgError` hierarchy. |
| `docker_runner.py` | Folded into `ContainerService`; SSH/fabric removed. |
| `kernel_builder.py` | docker-exec build; toolchain registry; fragments; Rust-ready; new base image. |
| `debuggee.py` | Two QEMU backends + typed argv command builder; accel via `HostProfile`. |
| `debugger.py` / `debugger.sh` | TCP gdbstub attach; drop PID-ns sharing; fix `gef-remote`. |
| `rootfs.sh` | Fix `resolv.conf` typo; arch-correct debootstrap. |
| Dockerfiles | Modern base; toolchains + Rust-ready in kbuilder; current gef/pwndbg. |
| `configs/*.ini` + `configs/fragments/*` | New keys (toolchain, accel mode); kconfig fragments. |
| `pyproject.toml` / lockfile | uv + PEP 621; Python 3.12; ruff-format; mypy; drop fabric/black/poetry. |
| `bootstrap` (justfile/script) | **NEW** — one-command host setup. |
| `.github/workflows/*` | Consolidate; add mypy + build-and-boot smoke. |

## 6. Testing strategy

- **Unit:** config validation; `HostProfile` detection (mock OS/arch/socket/kvm); QEMU
  argv builder across arch×accel×mode; toolchain registry; pipeline composition +
  partial/CTF/update modes; stage-skip logic — all asserting typed exceptions, not process
  exit. The existing ~140 tests are ported to the new structure.
- **Integration smoke (the real gate):** build a tiny kernel + boot + attach gdb + hit a
  breakpoint — arm64 (Mac native-HVF **and** Linux) and x86_64.

## 7. Definition of Done

One command, on macOS and Linux, builds and boots a modern **arm64** *and* **x86_64**
kernel and drops into a working GEF/pwndbg session with a breakpoint hit. arm64 on the Mac
is HVF-accelerated by default. Internals are the typed Pydantic → PipelineContext → Stage
pipeline with `ContainerService` / `Session`, errors-as-exceptions, and green CI including
mypy.

## 8. Out of scope (this sub-project)

- Sanitizer build profiles, symbolized panics, snapshot/restore, kernel-aware debugger
  plugins (Sub-project B).
- cpio unpack/repack, vuln playgrounds (Sub-project C).
- syzkaller integration, crash triage (Sub-project D).
- AI assistant pane (Sub-project E).
- Acceleration beyond HVF/KVM/TCG (e.g., colima nested-virt KVM-in-container) — documented
  as a future opt-in, not built here.
- Android kernels, additional architectures beyond arm64/x86_64.

## 9. Risks & open questions

- **macOS networking:** `host.docker.internal` reachability from the debugger container to
  native QEMU's gdbstub must be validated under colima specifically (not just Docker
  Desktop). Mitigation: smoke test early; fallback to a published-port/shared-network
  arrangement if needed.
- **Native QEMU artifact paths on macOS:** the debugger container needs the same `vmlinux`
  the host QEMU booted; ensure the bind-mount/host-path contract is unambiguous across
  in-container vs native modes.
- **Level 3 churn vs. green tests:** the overhaul is large. Sequence it so the typed
  config + pipeline scaffold land first, then port stages one at a time keeping tests
  green (detailed in the implementation plan).
- **clang-built kernels:** a few configs/targets historically prefer GCC. The toolchain
  registry + GCC opt-in is the escape hatch; smoke-test both.
- **colima resource defaults:** kernel builds are heavy; the bootstrap must provision
  adequate CPU/RAM or builds will be painfully slow.

## 10. Implementation sequencing (high-level; detailed plan to follow)

1. Tooling/bootstrap: uv + Python 3.12 + ruff/mypy/pre-commit; one-command host bootstrap;
   modern base image.
2. Core scaffold: `errors`, Pydantic `config`, `HostProfile`, `PipelineContext`,
   `ContainerService`, `Session` — with tests, before porting stages.
3. Port stages onto the new core one at a time (Download → Unpack → Build → Rootfs →
   Debuggee → Debugger), keeping tests green; fold in `docker exec`, toolchain registry,
   fragments, two QEMU backends, TCP attach, and the latent-bug fixes as each stage is
   touched.
4. CI: consolidate workflows; add mypy + build-and-boot smoke (incl. macOS-arm64 runner).
5. Validate Definition of Done on both hosts; update README.
