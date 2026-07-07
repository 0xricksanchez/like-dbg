# Foreign Kernel / CTF Adopt — Design (Branch 2c `feat/foreign-kernel`)

**Date:** 2026-07-07
**Sub-project:** B (Modern debugging UX) — slice **B6, part 3**: run + debug a provided (CTF) kernel.
**Branch:** `feat/foreign-kernel` (off `dev`, merged locally per the hard rule).
**Depends on / composes with:** the existing boot/debug plumbing (QEMU argv + gdbstub + tmux panes) and
Branch 1 crash intelligence (a foreign kernel that panics still produces a console-parsed crash report).
**Decisions recorded in:** ADR-0010; CONTEXT.md glossary (**Foreign kernel**, **Initramfs repack**).
**Status:** approved via brainstorming (2026-07-07); pending user review → writing-plans.

## 1. Purpose

Kernel-pwn CTF (and real-world triage) hands you a **kernel you did not build**: a `bzImage`/`Image` +
`vmlinux` + an `initramfs.cpio`, plus a `run.sh` with the exact boot cmdline. like-dbg today can only boot a
kernel it built from source (Download→Unpack→Build) or replay a cached build — every transport (SSH, 9p) and
verification (profile `.config`) assumes its own Debian rootfs. This slice lets you **`start_kgdb -c
<challenge>` a provided kernel**: boot it with the challenge's exact cmdline, attach gdb **with symbols**,
drive the (busybox) guest via the interactive console, and deliver an exploit into the foreign initramfs —
the full CTF loop, comfortably, inside like-dbg. Serves the project goal (bugs + blog posts) by making any
CTF/foreign kernel a first-class debug target.

Decomposed (during brainstorming) from 2b's non-goals + ADR-0009: 2a's guest transport can't reach a foreign
initramfs, and a foreign kernel has no `/ksrc` build tree — so this is a distinct subsystem, built here as
**one slice covering both halves**: **(A)** boot + debug a foreign kernel, and **(B)** deliver an exploit
into its foreign initramfs.

## 2. Goals / non-goals

**Goals:**
- **A — boot + debug a foreign kernel.** A `[foreign]` config (typically a per-challenge scenario) supplies
  the boot image, `vmlinux`, `initramfs`, the authoritative kernel `cmdline`, and optional extra QEMU args.
  `start_kgdb -c <challenge>` bypasses Download/Unpack/Build, boots the provided kernel + initramfs, attaches
  gdb with the provided `vmlinux` for symbols, and gives an interactive serial console pane.
- **Arch auto-detect** from the `vmlinux` ELF `e_machine` (override via `[foreign].arch`).
- **vmlinux auto-extract** from a `bzImage` when `[foreign].vmlinux` is absent (x86; wraps the
  `extract-vmlinux` logic in a container), else require it.
- **Authoritative cmdline:** `[foreign].cmdline` is used verbatim as the kernel append (like-dbg does NOT
  impose its own mitigation flags on a foreign kernel); like-dbg adds only `console=<serial>` (if missing)
  and the gdbstub. `extra_boot_args` still layers on top for toggle/append-while-testing; `[foreign].qemu_extra`
  mirrors the challenge's extra QEMU flags.
- **B — exploit delivery into the foreign initramfs** (no SSH/9p available):
  - **Repack-before-boot** (reliable): unpack the `initramfs.cpio(.gz)`, compile the exploit **static**
    (musl, from source) or copy a **prebuilt static binary**, inject at `/exploit`, repack → boot with it.
  - **Console-upload** (optional, live, **scoped**): chunked base64 over the serial into the guest shell,
    decode to `/tmp` — no reboot. Best-effort for **small** static exploits; **probe-gated** (guest must have
    `base64` + a writable `/tmp`, else a clear "use repack" error) and **verified** (byte-count + hash echoed
    back must match). Repack is the reliable fallback.
  - **The exploit is ALWAYS run manually** from the console — never auto-run (CTF is exploration; you
    `continue`, set breakpoints, then run `/exploit` yourself).

**Non-goals (deferred / out of scope):**
- **Building** a foreign kernel or its modules — a foreign kernel has no source tree/headers (2b's
  `ModuleBuildStage` is inert without `custom_modules` and can't build against a foreign kernel).
- **Auto-running** the exploit / an in-guest agent — deliberately excluded (ADR-0010).
- **Symbols from an *extracted* vmlinux** — CONFIRMED (2026-07-07): a `vmlinux` carved from a `bzImage` is
  **fully stripped** (no ELF `.symtab`, `nm` = 0; only embedded kallsyms data + code). So auto-extraction
  gives arch-detect + a base for raw gadget scanning, but **gdb has no function symbols**. For symbolized gdb,
  the challenge must supply `[foreign].vmlinux` (CTF challenges usually ship one for exactly this reason);
  extraction is the fallback that at least boots + attaches. A *provided* `vmlinux` gives whatever symbols it
  ships (symbol table; full source-line debugging only if it has DWARF).
- **Auto-detecting the challenge's QEMU args from its `run.sh`** — the user transcribes `cmdline`/`qemu_extra`
  into the scenario (a `run.sh` parser is a possible later nicety).
- 2a's SSH/9p transport for foreign guests — structurally impossible (no sshd/9p in a foreign initramfs);
  B's repack/upload replace it.

## 3. Decisions (brainstorm 2026-07-07)

1. **Interface = a `[foreign]` config section**, normally a per-challenge `configs/scenarios/<name>.toml`
   (`start_kgdb -c <name>`). Reuses the 6-layer TOML config + provenance + scenario machinery (reproducible,
   layered) instead of a parallel CLI surface. Presence of `[foreign].image` selects the foreign path.
2. **A + B in one slice** (the full CTF loop), per the user.
3. **Arch auto-detected from the `vmlinux` ELF**, `[foreign].arch` overrides. A wrong/`native` arch would
   silently boot the wrong emulator; the ELF header is authoritative + cheap.
4. **`vmlinux` auto-extracted from a `bzImage`** when absent (x86); arm64 `Image` requires an explicit
   `vmlinux`.
5. **Authoritative challenge `cmdline`** — no like-dbg mitigation flags imposed; only `console=` + gdbstub
   added; `extra_boot_args` layers for testing.
6. **Exploit delivery = repack (reliable core) + console-upload (optional live)**, **always manual run**.
7. **Repack/musl-compile run in a dedicated standalone container image** (`like_musl`, `.dockerfile_musl`:
   `cpio` + decompressors + **cross-musl toolchains for both arches**, §4.6), NOT on the host and NOT in the
   kbuilder image. `cpio -idm` needs root + device nodes (broken on macOS/colima); a Linux container sidesteps
   host root/deps and is unit-testable, and the cross-musl toolchains compile the exploit to the FOREIGN arch
   without emulation. The legacy standalone `ctf/misc/cpio.sh` stays as a manual helper for non-integrated use.
8. **Manifest-free foreign path.** A foreign run has no build/rootfs cache Manifest; `ForeignAdoptStage` sets
   the `ctx` fields directly (like a lightweight `--use`) and **skips ProfileVerification** (no `.config`).
   `run.json` records the foreign kernel/vmlinux/initramfs paths + a synthesized `foreign-<name>` label.

## 4. Architecture

### 4.1 Config — `ForeignCfg` (new `[foreign]` section)
`config.py` gains `ForeignCfg(_Base)` (frozen, extra=forbid), added to `Settings` + `_SECTION_MODELS`:
- `image: str = ""` (path to the boot image, abs or workspace-relative; **presence selects the foreign path**),
  `vmlinux: str = ""` (optional), `initramfs: str = ""` (optional), `cmdline: str = ""` (the append),
  `arch: str = ""` (optional override; else auto-detect), `qemu_extra: tuple[str, ...] = ()`,
  `exploit: str = ""` (optional, B — a source `.c` or a prebuilt static binary).
- Path fields accept **absolute paths OR workspace-relative** (a deliberate exception to the
  `_reject_unsafe_path` workspace-relative rule used for `patch_dirs`/`custom_modules`): foreign inputs are
  **read-only external artifacts** a CTF challenge ships anywhere (`~/ctf/<name>/`), mounted read-only into
  containers — so absolute is allowed; relative paths still reject `..` traversal. (A workspace `ctf/<name>/`
  layout stays the tidy, reproducible default.)

### 4.2 New host-side module — `src/likedbg/foreign.py` (deep seam)
- `ForeignKernel(image: Path, vmlinux: Path, initramfs: Path | None, arch: str, cmdline: str)` (frozen).
- `detect_arch(vmlinux: Path) -> str` — reads the ELF `e_machine` (`EM_X86_64=62` → `x86_64`,
  `EM_AARCH64=183` → `arm64`); raises `ForeignError` if not an ELF / unknown machine.
- `extract_vmlinux(container, image: Path, out: Path, *, image_name) -> Path` — runs the extract-vmlinux
  carve (gzip/xz/zstd/… → uncompressed ELF) in the `like_musl` container; returns the vmlinux path.
- `resolve_foreign(container, cfg: ForeignCfg, workspace: Path, *, out_dir: Path) -> ForeignKernel` —
  resolves paths, extracts vmlinux if absent, detects arch (override via `cfg.arch`), returns the
  `ForeignKernel`. **Called in `cmd_foreign` BEFORE `resolve_for_run`/host-profile/pipeline construction**
  (verified against `cmd_use`): the detected arch must be injected as `cli_overrides={"general": {"arch":
  <arch>}}` into `resolve_for_run` so `HostProfile.detect` (and therefore the QEMU binary / console / gdb
  arch) sees it — exactly as `cmd_use` injects `bm.arch`. So arch-detect + vmlinux-extract happen pre-pipeline,
  not inside `ForeignAdoptStage`.
- `repack_initramfs(container, *, initramfs: Path, exploit: Path, arch: str, out: Path, image) -> Path` —
  in the `like_musl` container: unpack `initramfs.cpio(.gz)`; if `exploit` is a `.c`, compile it static with
  the **arch-matched cross-musl** gcc (`{x86_64,aarch64}-linux-musl-gcc -static`), else copy the prebuilt
  static binary; inject at `/exploit`; repack (`find | cpio --format=newc -o [| gzip]`) to `out`; return it.
  (Compiling to the FOREIGN arch is why `arch` is threaded in.)
- `console_upload(session, pane, file: Path) -> None` — the scoped best-effort live path: first probe the
  guest (`command -v base64` + a writable `/tmp` write test) → clear `ForeignError` "use repack" if either
  fails; then send the payload as **chunked** base64 via `tmux send-keys` into a here-doc/`base64 -d >
  /tmp/<name>`, end-marked, and **verify** by echoing back a byte count + `sha256sum` (or `md5sum`) that must
  match the host's. Scoped to **small** static exploits (a few KB); repack is the reliable fallback for larger
  or when the probe fails.
- `ForeignError(LikeDbgError)`.

### 4.3 Stages
- **`ForeignAdoptStage`** (new): receives the pre-resolved `ForeignKernel` (from `cmd_foreign`) and sets
  `ctx.kernel_image` = image, `ctx.vmlinux` = the host vmlinux, `ctx.rootfs_image` = the initramfs, and
  stashes `cmdline`/`qemu_extra` for the argv builder (e.g. `ctx.foreign_cmdline`). It does NOT detect arch or
  extract vmlinux (those ran pre-pipeline in `cmd_foreign`, §4.2); `ctx.host.target_arch` is already the
  detected arch (via the `resolve_for_run` cli-override). No Manifest, no `.config`. It calls
  `recorder.record_kernel_paths(config=None, system_map="", vmlinux=<foreign vmlinux>, image=<foreign
  image>)` (verified: that method is a nicety — copies `.config` if present + writes pointer files — safe with
  `config=None` and no System.map), so `run.json`'s kernel pointers reflect the foreign artifacts without a
  synthesized Manifest.
- **`ForeignRepackStage`** (new, runs only when `cfg.exploit` set): `repack_initramfs(...)` → repoints
  `ctx.rootfs_image` at the repacked cpio (staged in the run dir).
- **`build_foreign_pipeline`** (new, mirrors `build_use_pipeline`): `ForeignAdoptStage → [ForeignRepackStage]
  → DebuggeeStage → DebuggerStage`. No Download/Unpack/Build, no ProfileVerification/Rootfs/ModuleBuild.
- `cli.main` dispatches `cmd_foreign` when `settings.foreign.image` is set (before the normal/`--use` flow).
  `cmd_foreign` mirrors `cmd_use`'s prelude: (1) `load_config` to read `settings.foreign`; (2) `resolve_foreign`
  (extract vmlinux if needed + `detect_arch`) → the `ForeignKernel`; (3) `resolve_for_run(scenario=…,
  cli_overrides={"general": {"arch": fk.arch}})` → host profile with the right `target_arch`; (4)
  `_ensure_images` (incl. `like_musl`), `RunRecorder.start`, `Session`; (5) `build_foreign_pipeline(...,
  foreign=fk, ...)`.

### 4.4 QEMU argv (`build_qemu_argv` — a foreign branch)
When a foreign cmdline is present, `build_qemu_argv` uses it VERBATIM as the `-append` base (skipping the
mitigation/root/console assembly it does for its own kernels), then ensures a `console=<ttyS0|ttyAMA0>` is
present (for the interactive pane + `console.raw`), appends `extra_boot_args`, and appends `qemu_extra` to the
argv. The initramfs routes through the existing `_rootfs_args` (`.cpio*` → `-initrd root=/dev/ram`). The
gdbstub (`-S -gdb tcp::<gdb_port>`) + the console chardev (`capture_console`, interactive stdio + logfile) are
added as today. `-kernel` = `ctx.kernel_image`.

### 4.5 gdb symbols (foreign vmlinux)
Reuse the debugger container's single `-v <mount_source>:/ksrc:ro` bind: `ForeignAdoptStage` sets the gdb
mount source to the **host dir holding the foreign vmlinux** and `ctx.vmlinux` = `/ksrc/vmlinux` (its
in-container path). gdb loads any vmlinux ELF for symbols — no source tree needed. Arch drives gdb `set
architecture`.

### 4.6 New image — `like_musl` (`.dockerfile_musl`)
Small Linux image: `FROM like_dbg_base` (or debian-slim) + `apt-get install cpio gzip xz-utils zstd lz4
lzop` (for unpack/repack + vmlinux carving) + **cross-musl toolchains for BOTH arches** —
`x86_64-linux-musl-gcc` and `aarch64-linux-musl-gcc` — so the exploit compiles to the FOREIGN arch
natively (no qemu emulation). Toolchains from pinned prebuilt tarballs (musl.cc) or `musl-cross-make`
(the plan pins an exact source; see §9 for the availability risk). Built by `images.build_images` /
`--build-images` (added to the image registry). `ForeignRepackStage` picks the cross-`gcc` matching the
foreign arch; `extract_vmlinux` uses the decompressors here.

## 5. Data flow (adopt → boot → debug → exploit)

1. `configs/scenarios/lk01.toml` `[foreign] image=… vmlinux=… initramfs=… cmdline=… [exploit=…]`.
   `start_kgdb -c lk01` → `ForeignAdoptStage` resolves paths, extracts vmlinux if needed, detects arch →
   sets `ctx`.
2. `[ForeignRepackStage]` (if `exploit` set) → repacks the initramfs with `/exploit` (musl-static / prebuilt).
3. `DebuggeeStage` boots the foreign kernel + initramfs with the challenge cmdline (+ console + gdbstub +
   qemu_extra) → the busybox guest to a shell in the interactive debuggee pane.
4. `DebuggerStage` attaches gdb with the foreign `vmlinux` → symbols; you set breakpoints.
5. `continue` in gdb → the guest runs. You drive the console shell; **manually** run `/exploit` (repacked) —
   or `start_kgdb --upload ./expl` (live) then run it. Set breakpoints first; observe. A panic is
   console-captured → B3 can produce a crash report.
6. Iterate: edit the exploit → `--upload` (live) or re-run `start_kgdb -c lk01` (repack + reboot).

## 6. Error handling

- `[foreign].image` missing/unreadable → clear `ForeignError` with the path.
- `vmlinux` absent AND extraction fails (e.g. arm64 `Image`, or an unrecognized container) → "provide
  `[foreign].vmlinux`".
- arch undetectable (not an ELF / unknown `e_machine`) AND `[foreign].arch` unset → error naming both fixes.
- `initramfs` missing when required for boot → error (a kernel with a built-in initramfs may boot without
  one; document the `root=` implications).
- cpio unpack/repack failure or musl compile failure → `ForeignError` with the container log tail.
- `--upload` — the guest probe (no `base64` / no writable `/tmp`) → `ForeignError` "use repack"; a
  post-transfer byte-count/hash mismatch → `ForeignError` (chunking corrupted it) → retry or use repack.
- A foreign run has no `guest` block / no `ssh_key` → `--run`/`--insmod`/`--rmmod` (2a/2b) refuse with a
  remedy pointing at the foreign repack/upload flow (they already error on a missing guest block).

## 7. Testing + live gate

- **Unit:** `detect_arch` on x86_64/aarch64 ELF-header fixtures + a non-ELF error; `resolve_foreign` path
  resolution + vmlinux-extract dispatch + arch override (fake container); `ForeignCfg` parse/validation
  (workspace-relative, presence-selects); `ForeignAdoptStage` sets `ctx.kernel_image`/`vmlinux`/`rootfs_image`/
  arch; `build_qemu_argv` foreign branch (verbatim cmdline + console added + qemu_extra + `-initrd` +
  gdbstub, NO mitigation flags); `repack_initramfs` builds the right `like_musl` container command
  (unpack/compile/inject/repack) via a fake container; `build_foreign_pipeline` stage order + dispatch;
  `--upload` send-keys sequence.
- **Live gate:** a small **CTF-style** target — a stripped `bzImage` (x86_64) + a busybox `initramfs.cpio.gz`
  + a `vmlinux` (with at least a symbol table). `start_kgdb -c <challenge>` boots it → interactive busybox
  shell in the pane → gdb attaches and **resolves a known symbol** (break e.g. `__x64_sys_open`, hit it) →
  repack-inject a tiny `/exploit` (musl-static) → `continue` → run `/exploit` manually from the console;
  also `--upload` a binary live → run it. If the exploit panics the kernel → console-captured crash report.
  arm64 `Image` variant as feasible (vmlinux provided). Record a transcript under `docs/superpowers/notes/`.

## 8. Docs

- **ADR-0010** — foreign-kernel adopt via a `[foreign]` scenario config (Manifest-free inject path, skip
  ProfileVerification, authoritative cmdline, arch auto-detect); exploit delivery = repack + optional
  console-upload, always-manual run; repack/musl in a standalone `like_musl` container.
- **CONTEXT.md** — add **Foreign kernel** and **Initramfs repack**.

## 9. Risks (for the live gate)

- **initramfs cpio format** variance (`newc` vs others; gzip vs raw vs xz) — unpack/repack must round-trip
  the guest's format; verify the repacked cpio boots.
- **musl-static vs the guest** — a busybox/musl initramfs runs a musl-static exploit; a glibc initramfs may
  need glibc-static (document; the `[foreign].exploit` prebuilt-binary path is the escape hatch).
- **cross-musl toolchain source** — Debian's `musl-tools` is native-only, so `like_musl` pulls cross toolchains
  (`{x86_64,aarch64}-linux-musl-gcc`) from musl.cc (a third-party host that is occasionally down → a
  build-reproducibility risk) or builds them via `musl-cross-make` (reproducible but ~10min/arch). The plan
  pins the exact source; the live gate builds the image once. Verify a cross-compiled static exploit runs on
  the foreign guest of each arch.
- **vmlinux extraction** across compression formats + stripped kernels (symbol table present?).
- **cmdline fidelity** — a missing/extra flag changes the challenge's behavior; `[foreign].cmdline` verbatim
  + only-console/gdbstub-added must not perturb it (verify the effective `-append`).
- **console-upload** reliability (base64 availability, paste chunking over the serial, large binaries).
- **arch mismatch** — a foreign vmlinux arch that disagrees with the image → wrong emulator; the ELF
  auto-detect + `set architecture` must agree.
