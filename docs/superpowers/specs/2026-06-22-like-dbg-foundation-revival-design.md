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
  `HostProfile.debuggee_mode`. Native HVF fires **only** for the accelerated same-arch
  case; everything else stays in-container:
  - **macOS + arm64 guest + HVF → `NativeQemu`** (`qemu-system-aarch64 -accel hvf -cpu
    host` on the host, reading `Image` + rootfs from the host path via the
    `(host_path, container_path)` contract). The *only* native path.
  - **macOS + x86_64 guest → `InContainerQemu` (TCG).** No `qemu-system-x86_64` on the
    host; the **debuggee container image stays in use on macOS** for x86_64.
  - **Linux + same-arch + `/dev/kvm` → `InContainerQemu` (KVM)** via device passthrough.
  - **Everything else (cross-arch, no-kvm) → `InContainerQemu` (TCG).**
  - **CTF context:** the supplied image + rootfs are staged under `workspace_dir`
    (`<workspace>/ctf/runs/<id>/`), not `/tmp`, so the mount + path-pair contract holds on
    macOS; CTF then rides the exact resolution above (an x86_64 challenge on macOS is
    in-container TCG — correct, slow).
  - All backends use a **typed QEMU command builder** emitting an **argv list, not a shell
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
- **Accel detection & degradation policy.** `HostProfile` resolves accel: macOS →
  `sysctl kern.hv_support == 1` + `qemu-system-aarch64` on PATH ⇒ HVF (arm64 only);
  Linux → `/dev/kvm` present + accessible (probe; user in `kvm` group) ⇒ KVM; override
  `accel = auto|kvm|hvf|tcg`. **Policy by intent:** `auto` (default) **degrades gracefully
  to in-container TCG and never crashes**; an explicit `accel = hvf|kvm|tcg` that is
  unsatisfiable **hard-errors**. CI sets `accel = tcg` explicitly for deterministic runs.
- **Actionable diagnostics (cross-cutting).** Degradation warnings and `LikeDbgError`s
  follow a **"what's wrong + how to fix"** shape, e.g. `⚠ qemu-system-aarch64 not found on
  host → falling back to in-container TCG (slow). Run 'just bootstrap' for HVF.` Every
  fallback or failure states both the cause and the remedy.

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

### 4.6 Workspace & storage strategy

The Linux kernel tree contains files differing only by case (e.g. `xt_CONNMARK` vs
`xt_connmark`). On a default **case-insensitive APFS** volume the tree is silently
corrupted on unpack — so source must live on **case-sensitive storage**. We auto-select one
of two modes (override: `mac_storage = auto|bind|volume`; `auto` is default):

- **Bind mode** — Linux always; macOS when `workspace_dir` is detected on case-sensitive
  storage. Source tree on the bind-mounted host path; uniform `(host_path, container_path)`
  contract; **host-editable source**; native QEMU reads artifacts directly.
- **Volume mode** — the **zero-setup macOS default** when `workspace_dir` is
  case-insensitive. The unpacked + built kernel tree (and the rootfs chroot) live in a
  **Docker named volume on colima's ext4** (case-sensitive by nature) — *no disk fiddling,
  no APFS volume creation*. The host-consumable single files (`Image` + rootfs image, which
  cannot collide) are **exported to the bind-mounted APFS workspace** for native QEMU; the
  **debugger container mounts the source volume (ro)** for `vmlinux` + source + `lx-`
  scripts (no export). `custom_modules`/patches are host inputs the build container applies
  into the in-volume tree.

Consequences: the unpack step moves **into a container** (consistency + always
case-sensitive). The `(host_path, container_path)` pair generalizes to a **workspace
strategy** that, per artifact, knows its producer store (bind path or volume) and — only in
volume mode for host-consumed single-file artifacts — an exported host path. On macOS the
bootstrap **detects** case-sensitivity and selects the mode (it never creates/mutates disk
volumes); it surfaces which mode is active via the §4.4 diagnostics shape.

**State layout (consolidated, gitignored).** All generated/cached state lives under one
defined layout (on the workspace path in bind mode; in the named volume for source/build in
volume mode): `kernels/` (download cache), `ccache/` (compiler cache — a plain dir, not an
opaque volume, so it survives image rebuilds and is inspectable), `build/<kernel-id>/`
(unpacked + built source), `images/` (rootfs images), `ctf/runs/<id>/` (CTF artifacts),
`.state/` (small bookkeeping, e.g. gdb-script-hash). **The builder SSH keypair is removed
entirely** (`docker exec` needs no keys); the only SSH keys that remain are the **guest**
keys the rootfs generates for logging into the debuggee over the `:10021` forward — one
fewer keypair, smaller security surface.

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

**Guaranteed (not best-effort) deliverables:**

- **Full native-Linux support:** x86_64 and arm64 hosts, in-container KVM acceleration.
- **x86_64 support on every host**, including in-container TCG on the arm64 Mac.
- **Cross-build support both directions:** x86_64 kernel *and* x86_64 rootfs built from the
  arm64 Mac, and arm64 built from an x86_64 Linux host. (Kernel cross-build via the
  clang-universal-cross toolchain; rootfs cross-build via foreign-arch debootstrap +
  bootstrap-provisioned binfmt.)

The only **non-blocking bonus** is the 5.15 example building under the modern toolchain.

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
- **APFS case-insensitivity (resolved by §4.6):** kernel source must be on case-sensitive
  storage. Handled by the bind/volume workspace strategy — *no* per-user disk fiddling.
  Residual: in **volume mode**, the artifact-export step (`Image` + rootfs → APFS) must be
  correct and kept in sync so native QEMU boots what was just built; in **bind mode**,
  virtiofs throughput for a multi-GB source tree may slow builds (ccache mitigates).
- **colima named-volume sizing:** a built kernel tree + ccache is several GB inside the
  colima VM; the bootstrap must size the VM disk accordingly.
- **Level 3 churn vs. green tests:** the overhaul is large. Sequence it so the typed
  config + pipeline scaffold land first, then port stages one at a time keeping tests
  green (detailed in the implementation plan).
- **clang-built kernels:** a few configs/targets historically prefer GCC. The toolchain
  registry + GCC opt-in is the escape hatch; smoke-test both.
- **colima resource defaults:** kernel builds are heavy; the bootstrap must provision
  adequate CPU/RAM or builds will be painfully slow.

## 10. Branching, integration & sequencing

### 10.1 Branching strategy (hard constraint)

- **`main` stays untouched** for the entire rework.
- All rework integrates on a long-lived **`dev`** branch (forked from `main`).
- Each milestone/chunk is built on a short-lived **feature branch off `dev`** and merged
  back into `dev`.
- **`dev → main` happens only at the very end**, as a single deliberate replacement once
  the full rework is validated. (`2026_rework` is a pre-existing empty branch == `main`;
  unused.)

### 10.2 Milestone 1 — Full arm64 experience (with an early plumbing checkpoint)

M1 delivers the **complete arm64 experience on macOS, start to finish**: build a modern
kernel → boot to an interactive shell under native HVF → attach the containerized debugger
via `host.docker.internal` → set/hit breakpoints during normal operation, all wired into
the tmux session. Tooling + bootstrap (uv + Python 3.12 + ruff/mypy/pre-commit + modern
base image) and the typed-core scaffold (`errors`, Pydantic `config`, `HostProfile`,
`PipelineContext`, `ContainerService`, `Session`) land first.

**Early internal checkpoint (de-risk gate):** before building out the full experience, hit
the **minimal plumbing PoC** — an early-boot breakpoint (`break start_kernel; continue`) on
the arm64/HVF target. This exercises every risky link (the `(host_path, container_path)`
contract, the container→host gdbstub hop, HVF acceleration, symbol loading) and fails
loudly if any is broken, so the topology is proven before the rest of M1 is built on it.

**M1 exit gate:** the full usable arm64 session above — boot-to-shell + interactive
breakpoints in the tmux session — not just the early-boot PoC.

### 10.3 Milestone 2 — Breadth

x86_64 target; all build modes (generic/syzkaller/custom/config via kconfig fragments) +
`extra_args`; CTF context; `partial`/`update_containers` modes; full test-suite port; CI
consolidation + mypy + build-and-boot smoke (incl. a macOS-arm64 runner); the 5.15 example
as a non-blocking secondary check; README refresh. Same Level 3 end state — the scary
unknowns are simply resolved in M1 rather than at the finish line.
