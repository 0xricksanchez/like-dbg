# Custom Modules (2b) — Live Gate Transcript

**Date:** 2026-07-07
**Branch:** `feat/custom-modules` (off `dev`), HEAD `0ccab43`
**Plan:** `docs/superpowers/plans/2026-07-06-custom-modules.md` (Task 10)
**Host:** M5 MacBook Pro, colima (aarch64, Virtualization.Framework), tmux
**Result:** ✅ BOTH ARCHES PASSED (arm64 native/HVF + x86_64 in-container/TCG)

Gate driven controller-side: `start_kgdb` in a detached tmux session, `continue` via `tmux send-keys`,
`--insmod`/`--rmmod`/`--run` from the host, artifacts read from `artifacts/runs/latest/`.

## What the gate validates
The full 2b loop, end-to-end, composing 2a (guest transport) + B3 (crash intel):
kernel build (with the new `CONFIG_MODULE_FORCE_UNLOAD` profile fragment) → `ModuleBuildStage` builds the
out-of-tree `lk01.ko` against the fresh tree → `--insmod` loads it over SSH → reload / `--force-unload` →
compile the PoC → `--run` the PoC → the deliberate `copy_from_user` overflow → kernel crash event → B3
auto-produces the crash report.

## arm64 native (HVF) — run `20260707T063129Z`, kernel `linux-6.6.30-9977d7c3`
- `configs/local.toml`: `[build] custom_modules = ["modules/lk01"]`.
- **Fresh kernel rebuild 9m57s** (cache miss — the `module-unload.config` fragment changed exploit-dev's
  `.config`). **Profile verification PASSED** — `CONFIG_MODULE_FORCE_UNLOAD=y` is a *hard* expect, so this
  proves the T8 fragment took effect.
- **`ModuleBuildStage` built `lk01.ko` in 10s** → staged `exploit/modules/lk01.ko` (232k) **+
  `lk01.ko.hash`** (`linux-6.6.30-9977d7c3:<sha>` — canonicalize + content-hash sidecar working live).
  `modinfo` vermagic `6.6.30 SMP preempt mod_unload aarch64` matches the kernel.
- `continue` → 32KB boot to login → SSH in with the baked key.
- `--insmod ./modules/lk01` → `loaded lk01 (rc=0)`. Guest: `lsmod` shows `lk01`, `/dev/lk01` is a
  `crw-` char device (`misc_register`), `dmesg` "lk01: loaded, /dev/lk01 ready".
- **Reload:** `--insmod ./modules/lk01` again → `rc=0` (rmmod+insmod). **`--rmmod lk01 --force-unload`** →
  `rc=0` (proves `CONFIG_MODULE_FORCE_UNLOAD`).
- PoC: `clang -static` in the kbuilder container → 716k aarch64 `lk01_expl`. `--run ./exploit/lk01_expl`
  completes 20s (2a keepalive) → **kernel OOPS** → `crash.json`/`crash.md`, `status: crashed`; `class=oops`,
  `fatal`, a `die` at the **arm64 BRK handler** (stack-protector `__stack_chk_fail`) with a **"corrupt
  stack?"** backtrace — the exact `copy_from_user(kbuf[64], …, 4096)` stack smash.

## x86_64 in-container (TCG, published) — run `20260707T064651Z`, kernel `linux-6.6.30-e4b82039`
- `configs/local.toml`: `[general] arch="x86_64"` + `[build] custom_modules=["modules/lk01"]`.
- **Fresh x86_64 kernel rebuild 3m25s** (cache miss); rootfs cache-hit (`d3451df3`, from 2a). host.json:
  in-container / published; **2222 published** on the host.
- **`ModuleBuildStage` built `lk01.ko` 10s** (172k, vermagic `6.6.30 SMP preempt mod_unload` matches).
- `continue` → 40KB TCG boot to login → SSH in (published 2222).
- `--insmod ./modules/lk01` → `loaded lk01 (rc=0)`. Guest: `uname -m`=x86_64, `lsmod`=`lk01`, `/dev/lk01`
  registered, dmesg "lk01: loaded".
- PoC compiled **in-guest** (kbuilder image is arm64 → can't cheaply cross a userspace x86_64 binary;
  compiled with the guest's `gcc -static` over the 9p share). `--run ./exploit/lk01_expl` →
  x86_64 **FORTIFY `__copy_overflow`** caught the oversized copy: dmesg
  `Buffer overflow detected (64 < 4096)!`, `WARNING … __copy_overflow`, `Modules linked in: lk01(O)`,
  `Comm: lk01_expl`, and the **Call Trace names `lk01_ioctl+0xf3/0x100 [lk01]`** (module-symbolized).
  B3 captured it → `crash.json`/`crash.md`, `class=warn`, `fatal=False` → `status: launched` (correct —
  a WARN is non-fatal per the crash-intel §6).

## Arch difference (expected, both valid)
The same `copy_from_user(kbuf[64], user_ptr, 4096)` triggers different detectors: arm64 → the stack
protector fires a BRK → `die`/oops (fatal, `status crashed`); x86_64 → FORTIFY's `__copy_overflow` runtime
check rejects the copy → WARN + `-EFAULT` (non-fatal, `status launched`). Both are captured by B3 with the
crash implicating the `lk01` driver, and both prove 2b's tooling loop end-to-end.

## Cross-task confirmations (opus final-review paths, live)
- Toolchain/vermagic: the `ModuleBuildStage` `.ko` vermagic matches the freshly-built kernel on both arches
  (same `recipe.env()` toolchain).
- `stage_module` canonicalize + content-hash sidecar produced `<dir>.ko` + `<dir>.ko.hash` live.
- `--insmod` (Docker for build/modinfo, SSH for load) reaches the guest at `127.0.0.1:2222` in native-HVF
  and in-container/published modes; `--force-unload` works with the new profile fragment.
- Zero leftover containers after teardown on both arches.

**Verdict: custom-modules 2b is live-gated on both arches. Ready to merge to `dev` (local).**
