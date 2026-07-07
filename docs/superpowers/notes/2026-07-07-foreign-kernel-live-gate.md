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
| repacked cpio round-trips; injected `/exploit` is the correct FOREIGN arch | ✅ | ✅ |
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

## Environment finding — cross-musl COMPILE path blocked on THIS host (decision needed)

The musl.cc cross toolchains baked into `.dockerfile_musl` are **`ELF 32-bit LSB, Intel i386`
(x86-host) binaries** for BOTH targets. This colima has **no working x86 emulation** (amd64
containers fail `exec: no such file or directory`; a `tonistiigi/binfmt --install amd64` registered
`qemu-x86_64` but execution still failed — colima was not started with x86 emulation). So the
`.c`-compile branch of `repack_initramfs` (`{x86_64,aarch64}-linux-musl-gcc -static`) **cannot run
on this machine** for either arch.

The **prebuilt-static-binary** delivery path (`[foreign].exploit = <binary>`, repack's `cp` branch)
needs no cross-gcc and was validated end-to-end here for both arches. The reliable delivery mechanic
(unpack → inject → repack → round-trip) is proven; only the in-container *compile* is gated on the
toolchain/emulation.

**Remediations (user decision — not changed autonomously):**
- **(a)** Give colima x86 emulation: `colima start --vz-rosetta` (Apple Virtualization + Rosetta),
  then `like_musl` should be built/run as `--platform linux/amd64` so the x86-host toolchains run.
  Matches the "x64 emulated on mac" intent. Cheapest; keeps musl.cc.
- **(b)** Switch `.dockerfile_musl` to **`musl-cross-make`** (the spec §9 fallback): builds
  arm64-**host** → {x86_64, aarch64} musl toolchains that run natively on Apple Silicon with no
  emulation. Reproducible; ~10–20 min image build.
- **(c)** Use **`zig cc`** (single arm64-native binary, `-target {x86_64,aarch64}-linux-musl -static`).
  Cleanest/fastest, but a toolchain design change from the spec.

Recommendation: (a) if the user already runs Docker Desktop / colima-rosetta elsewhere (most CTF
setups do); otherwise (b) for a self-contained, emulation-free image.

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
