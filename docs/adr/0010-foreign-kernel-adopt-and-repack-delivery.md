# Foreign kernel adopt via a `[foreign]` scenario; exploit delivery by initramfs repack + console upload

CTF and triage hand you a kernel you did not build — a `bzImage`/`Image` + `vmlinux` + `initramfs.cpio` +
the challenge's exact boot cmdline. 2c (`feat/foreign-kernel`) lets `start_kgdb -c <challenge>` **adopt and
debug** it. A new `[foreign]` config section (normally a per-challenge scenario) supplies the image,
`vmlinux`, `initramfs`, authoritative `cmdline`, and optional extra QEMU args; a **Manifest-free**
`ForeignAdoptStage` sets `ctx.kernel_image`/`ctx.vmlinux`/`ctx.rootfs_image` directly (like a lightweight
`--use`), **bypassing Download/Unpack/Build and skipping ProfileVerification** (a foreign kernel has no
source tree and no `.config`). Arch is **auto-detected from the `vmlinux` ELF** (`[foreign].arch` overrides);
`vmlinux` is **auto-extracted from a `bzImage`** when absent. Because a foreign initramfs has no sshd/9p/baked
key, exploit delivery is **repack-before-boot** (unpack the cpio, compile the exploit static / drop a prebuilt
binary at `/exploit`, repack, boot) plus an optional **console-upload** (base64 over the serial); the exploit
is **always run manually** from the console.

## Considered Options

- **Extend `--adopt` to take a bare `bzImage`+`vmlinux`.** Rejected: `--adopt` migrates a full in-volume
  kernel *source tree* (parses `Makefile` VERSION, checks the `.config` compiler, needs `arch/<arch>/boot/`).
  A provided image pair has none of that. The foreign path shares nothing with source-tree adoption; a
  dedicated Manifest-free inject path (modeled on `--use`, which already hydrates `ctx` from paths) is the
  right seam.
- **Impose like-dbg's own boot-arg/mitigation config on foreign kernels.** Rejected: a foreign kernel's
  mitigations are the challenge's to decide (baked into its config + `run.sh` cmdline). `[foreign].cmdline`
  is used **verbatim**; like-dbg adds only `console=` (for the interactive pane + `console.raw`) and the
  gdbstub. `extra_boot_args` still layers on top so the operator can toggle/append flags while testing.
- **Reuse 2a's SSH/9p transport for the foreign guest.** Structurally impossible: a foreign CTF initramfs
  (busybox, no sshd, no 9p, no baked key, no like-dbg rootfs Manifest) exposes only the serial console. So
  `--run`/`--insmod`/`--rmmod` cannot apply; they already refuse on a missing `guest` block. Delivery is
  repack (reliable) + console-upload (live when the guest has `base64` + tmpfs).
- **Auto-run the injected exploit** (e.g. patch the initramfs `init`). Rejected on the same principle as 2b's
  load-on-command: CTF is exploration — you `continue`, set breakpoints, and run `/exploit` yourself. The
  exploit is never auto-run.
- **Shell out to `ctf/misc/cpio.sh` for repack/musl-compile.** Rejected: it runs on the host, needs **root**
  (`cpio -idm` device nodes) + host `cpio`/`musl-gcc`, and is fragile/broken on macOS/colima; it isn't
  unit-testable and its exit codes don't compose. Instead the unpack/repack + static compile run in a
  dedicated standalone `like_musl` container (`.dockerfile_musl`: `cpio` + decompressors + **cross-musl
  toolchains for both arches** — `x86_64-linux-musl-gcc` and `aarch64-linux-musl-gcc`, pulled prebuilt from
  musl.cc — so the exploit compiles to the *foreign* arch with no QEMU emulation; Debian's `musl-tools`
  package is native-only and cannot cross-compile to the foreign arch, so it does not fit here. musl.cc is a
  third-party host (occasional downtime is a build-reproducibility risk); `musl-cross-make` is the fallback
  if a prebuilt toolchain becomes unavailable. This sidesteps host root/deps and stays unit-testable.
  `cpio.sh` remains a manual helper for non-integrated use.
- **Require the operator to declare the arch.** Rejected as a footgun (a wrong/`native` arch silently boots
  the wrong emulator). The `vmlinux` ELF `e_machine` is authoritative and a ~4-byte read; `[foreign].arch` is
  kept only as an override/fallback (bzImage-only, pre-extraction).

## Consequences

- A new `like_musl` image joins the registry (`--build-images`). `ForeignRepackStage` and `extract_vmlinux`
  run inside it; no host `cpio`/`musl`/root.
- Foreign runs are Manifest-free: `run.json` records the foreign image/vmlinux/initramfs paths and a
  synthesized `foreign-<name>` label; no build/rootfs cache entry is created. ProfileVerification and
  ModuleBuild/Rootfs stages are absent from `build_foreign_pipeline`.
- A stripped release `vmlinux` yields only the symbols it carries (symbol table + base for gadget work); full
  source-line debugging needs a `vmlinux` with DWARF.
