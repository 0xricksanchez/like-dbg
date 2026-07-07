# Foreign-kernel live gate — 2026-07-07 (feat/foreign-kernel)

Live-gate run of the foreign-kernel / CTF-adopt slice (spec §7). Host: Apple Silicon mac,
colima (Docker 29.5.2), QEMU 10.x for both arches, `like_musl:latest` built locally.
The gate drives the **real** `like_musl` container and the **real** `likedbg.foreign`
functions (not mocks), for both target arches (x86_64 + arm64).

## What the live gate validated (PASS)

Driven via `scratchpad/livegate2.py` against the real image + real docker, both arches:

| Check | x86_64 | arm64 |
|---|---|---|
| `like_musl` image builds | ✅ (arm64 image) | ✅ |
| `repack_initramfs` — **same-dir** initramfs+exploit layout (real container) | ✅ | ✅ |
| `repack_initramfs` **`.c`-compile** branch (`zig cc` cross-compile, arm64 host, no emulation) | ✅ | ✅ |
| repacked cpio round-trips; injected `/exploit` is the correct FOREIGN arch + static | ✅ | ✅ |
| `detect_arch` on a real ELF | ✅ (x86-64) | ✅ (aarch64) |
| `resolve_foreign` (provided vmlinux) | ✅ | ✅ |
| `build_qemu_argv` foreign branch: verbatim cmdline, `console=<ttyS0/ttyAMA0>`, NO imposed mitigations, `-initrd`, gdbstub, `qemu_extra`, correct QEMU binary | ✅ | ✅ |

Unit suite at branch tip: **443 passed**, ruff + ruff-format clean, mypy strict clean (43 files).

## Bugs the live gate caught (both fixed)

1. **Container-mount collision (Critical, fixed `5e5d2d8`).** `repack_initramfs`/`extract_vmlinux`
   keyed the docker `volumes` dict by each file's *parent dir*. A CTF that ships the initramfs and
   `exploit.c` in the **same directory** (the standard `~/ctf/<name>/` layout — exactly what
   `configs/scenarios/example-foreign.toml.example` shows) collapsed the dict, dropping the `/in`
   bind, so `gzip -dc /in/...` failed on the common case. Unit tests missed it (they used three
   separate dirs). Fixed with a `_dedup_mounts` helper (dedups by host dir, upgrades to rw if any
   role needs it, rebases each container path); regression tests for the same-dir case added.

2. **`guest_net`/`share` leak into foreign runs (Important, fixed `7b8a927`).** Foreign runs left
   `guest_net`/`share` at their `True` defaults, so QEMU silently added `-netdev`/`-device virtio-net`
   + `-virtfs` 9p (devices the challenge never specified), and `run.json` got a spurious `guest`
   block — contradicting ADR-0010's "serial console only" promise and making `--run`/`--insmod`
   SSH-fail instead of cleanly refusing. Fixed by forcing `guest_net=False`/`share=False` on the
   foreign `RunResolution.effective_debuggee` (one shared seam feeding both the argv and run.json).

## Toolchain finding → RESOLVED with `zig cc` (2026-07-08)

**Original finding (musl.cc, 2026-07-07):** the musl.cc cross toolchains baked into `.dockerfile_musl`
were **`ELF 32-bit LSB, Intel i386` (x86-host) binaries** for BOTH targets, and this colima has no
working x86 emulation (amd64 containers fail `exec: no such file or directory`; a
`tonistiigi/binfmt --install amd64` registered `qemu-x86_64` but execution still failed — colima was
not started with x86 emulation). So the `.c`-compile branch could not run here for either arch.

**Resolution (requirement: work on {mac, linux} × {x86_64, arm64}):** `.dockerfile_musl` now uses
**`zig cc`** (pinned zig 0.14.1, arch-matched at build time) behind thin `x86_64-linux-musl-gcc` /
`aarch64-linux-musl-gcc` wrappers (so `repack_initramfs` is unchanged). `zig cc` is one host-native
binary that cross-compiles static musl to both targets from any host arch with no emulation. Verified
2026-07-08 on this arm64 mac — the full `.c`-compile path (`repack_initramfs`) now passes for BOTH
arches:

```
x86_64: injected /exploit = ELF 64-bit LSB executable, x86-64, statically linked   [OK]
arm64 : injected /exploit = ELF 64-bit LSB executable, ARM aarch64, statically linked [OK]
```

Rejected alternatives: (a) `colima --vz-rosetta` + `--platform linux/amd64` — depends on host x86
emulation, doesn't satisfy "no emulation, any host"; (b) `musl-cross-make` — reproducible but ~10–20
min build per arch and host-arch-specific. `zig cc` is host-agnostic and fast. The prebuilt-binary
`cp` branch remains for a glibc initramfs or a pre-built exploit.

## Not runnable autonomously (manual human step)

The full interactive loop — `start_kgdb -c <challenge>` → busybox shell in a tmux pane → gdb attaches
and resolves a symbol (`break __x64_sys_open`, hit it) → `continue` → run `/exploit` manually → and the
live `--upload` path — requires an interactive tmux session with human-observed panes and a real CTF
kernel (bzImage/Image + symbolized vmlinux + busybox initramfs), neither of which exists in this repo.
Recipe for the user, once artifacts are in `ctf/<name>/` and a scenario is written:

```
tmux new -s dbg
./start_kgdb -c <name>          # boots the foreign kernel; gdb attaches with the provided vmlinux
# in gdb pane:  break start_kernel  (or a challenge symbol);  continue
# in debuggee pane (busybox):  /exploit        # repack path — run manually
# live delivery instead:  ./start_kgdb --upload ./expl   (optional; repack is the reliable fallback)
```

Known live-path caveat to watch (deferred — needs a real console to tune): `console_upload`'s
`_console_tail_reader` returns the first non-empty console read, which can be the shell's *echo of the
probe command* rather than its output → a spurious "guest lacks base64" (fail-safe: falls back to
repack). Harden against a real console before relying on `--upload`.
