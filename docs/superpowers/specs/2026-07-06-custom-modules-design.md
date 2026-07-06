# Custom Modules — Design (Branch 2b `feat/custom-modules`)

**Date:** 2026-07-06
**Sub-project:** B (Modern debugging UX) — slice **B6, part 2**: out-of-tree custom kernel modules.
**Branch:** `feat/custom-modules` (off `dev`, merged locally per the hard rule).
**Depends on / composes with:** Branch 2a (`feat/exploit-loop`) — the 9p **Guest share** + SSH transport +
`--run` loop; Branch 1 (`feat/crash-intel`) — a module that faults the kernel auto-produces a crash report.
**Decisions recorded in:** ADR-0009; CONTEXT.md glossary (**Custom module**, **Module build**).
**Status:** approved via brainstorming (2026-07-06); pending user review → writing-plans.

## 1. Purpose

Kernel exploitation and kernel-pwn CTF revolve around a **loadable vulnerable module**: you build (or are
handed) a `.ko`, load it into a matching-kernel guest, then exploit it. Today `build.custom_modules` is a
validated-but-inert config slot (B1 left the schema; nothing builds it). This slice wires the missing
build-and-load path: compile an **out-of-tree** module against the already-built kernel tree, stage the
`.ko` into the 2a **Guest share**, and load it into the live Debuggee on command — feeding straight into
the `--run` exploit loop and the crash detector. Serves the project goal (bugs + blog posts): a tight
edit → build module → load → exploit → observe (→ crash) inner loop, with no kernel rebuild and no reboot.

## 2. Goals / non-goals

**Goals (both arches):**
- **Out-of-tree `obj-m` build** of each `custom_modules` entry against the built kernel tree in the
  `likedbg_ksrc` volume (`/ksrc/<label>`), using the **same toolchain env** as the kernel build (`ARCH`,
  `LLVM=1`) so vermagic/ABI match and `insmod` succeeds.
- **Prebuilt `.ko` passthrough:** a `custom_modules` entry (or `--insmod` argument) that is already a `.ko`
  skips the build. Scoped to a `.ko` whose **vermagic matches the like-dbg-built kernel** — e.g. one you
  built externally against this kernel, or a reload of a previously built `.ko`. Loading a `.ko` built for
  a *foreign* kernel is out of scope (see the 2c non-goal); on a vermagic-mismatch `insmod` we surface the
  guest `dmesg` line + remedy rather than pretending to force it.
- **Build at boot:** a pipeline stage builds each configured module during `start_kgdb` and stages the
  `.ko` into the Guest share (`<share_dir>/modules/`), ready the moment the guest is up.
- **Load on command:** `start_kgdb --insmod [PATH]` (pure host, re-runnable against the live `latest` run)
  delivers the `.ko` and loads it over SSH; reload = `rmmod`-then-`insmod`. No auto-`insmod` at boot.
- **Reload / unload:** `--insmod` on an already-loaded module reloads it; `--rmmod NAME` unloads.
- **Seeds:** an out-of-tree `obj-m` template + a small original deliberately-vulnerable **LK01-style ioctl
  driver** with a crash-triggering PoC, so `custom_modules=["modules/lk01"]` + `--insmod` + `--run` is a
  working vuln→exploit→crash demo (the PoC binary is built per a documented one-liner — §4.6; 2b itself
  builds only the `.ko`).

**Non-goals (deferred / out of scope):**
- **In-tree module injection** (the legacy `custom_modules` semantics: copy into the kernel source tree,
  add Kconfig, `CONFIG_*=y/m`, build as part of `make all`). Superseded by out-of-tree here (ADR-0009).
  Built-in (`=y`) vuln code compiled into `vmlinux` stays a kernel-build concern (`patch_dirs` /
  `extra_fragments`), not `custom_modules`.
- **Auto-`insmod` at boot** (a rootfs boot hook). Rejected: it runs the module's `init` before you can arm
  gdb, defeating init-time debugging (§3.3).
- **A GDB symbol-autoload helper** (`lx-symbols` wiring / auto `add-symbol-file`). That is **B4** (the GDB
  helper pack). 2b only guarantees the `.ko` sits at a known guest path so `add-symbol-file`/`lx-symbols`
  can find it; it prints that path on load.
- **Foreign kernel adoption — the CTF "bring-your-own-kernel" shape — deferred to a follow-up spec (2c).**
  Booting a provided `bzImage`+`vmlinux` (vuln baked into the kernel), a foreign initramfs/cpio rootfs, and
  a console/init-based path to load a provided `.ko`, is a **distinct subsystem**: a foreign kernel has no
  `/ksrc` build tree (so modules can't be built out-of-tree against it — only prebuilt `.ko`s that already
  match it can load), and 2a's SSH+9p transport exists only because *our* `rootfs.sh` bakes sshd + the 9p
  mount — a foreign CTF initramfs has neither, so `--insmod`'s delivery does not reach it. 2b targets a
  kernel like-dbg built; 2c will own foreign-kernel boot + a non-SSH delivery path.
- **Module signing**, early-boot/initramfs module loading, cross-module `EXPORT_SYMBOL` graphs.
- **`--force` / vermagic override** on `insmod`. Rejected as wishful thinking: the vermagic check is
  in-kernel and `insmod` cannot override it; `modprobe --force` only strips a field or two and is
  unreliable. A mismatch is surfaced with a clear remedy instead (§6).
- Building the guest-side exploit binary — that is the user's `--run` payload (2a), not a module.

## 3. Decisions (brainstorm 2026-07-06)

1. **Build model = out-of-tree `obj-m`.** Build with `make -C /ksrc/<label> M=<modsrc> modules` against the
   already-built tree; no kernel rebuild, no cache invalidation of the kernel. This is the fast inner loop
   and matches the ROADMAP's "out-of-tree … + auto-insmod" framing. The legacy in-tree injection is
   retired. (Grill: out-of-tree covers ~all live vuln research + kernel-pwn CTF; the only real gaps —
   built-in `=y` vuln, early-boot load — are rare and out of scope. See ADR-0009.)
2. **Prebuilt `.ko` is a first-class input.** Build-from-source and load-a-binary share one deliver→load
   path; a `.ko` argument skips the build.
3. **Interface = a boot-time build stage + a re-runnable `start_kgdb --insmod`.** The stage builds +
   stages every configured module (ready at boot). `--insmod [PATH]` (mirrors `--run`) builds-if-stale,
   delivers, and loads on demand — the reload path that keeps the loop fast without a session restart.
4. **Load on command, never auto-`insmod` at boot.** For exploitation you `continue` past `start_kernel`,
   arm gdb (breakpoint `do_init_module`, or source the kernel's `lx-symbols`) **while the module is
   unloaded**, then `--insmod` — and gdb catches the module's `init` as it maps. Auto-load would run `init`
   before you can arm gdb.
5. **`.ko` lives in the Guest share** at `<share_dir>/modules/` → guest `/mnt/exploit/modules/` — zero-copy,
   live, crash-durable, reuses 2a wholesale. No rootfs rebake (rejected: ties module identity to the
   rootfs cache key + forces a rootfs rebuild per module edit).
6. **Same toolchain as the kernel.** The module build uses `recipe.env()` (`ARCH` + `LLVM=1` for clang, or
   `CROSS_COMPILE` for gcc) — identical to `BuildStage` — so the `.ko` vermagic matches and unsigned
   `insmod` is accepted (`CONFIG_MODULE_SIG` is unset; `CONFIG_MODULES=y`, `CONFIG_MODULE_UNLOAD=y`).
7. **Module edits do not rebuild the kernel.** `custom_modules` is NOT added to the kernel `BuildRecipe`
   cache key. The module stage rebuilds a `.ko` only when the module source's **content hash** (via the
   existing `input_hash`, which ignores `.o`/`.ko`/`.mod` litter) differs from the hash recorded beside the
   staged `.ko`, or the kernel `label` changed. Content hashing (not mtime) matches the codebase's cache
   discipline and avoids a silent-stale `.ko` after a git checkout resets mtimes.

## 4. Architecture

### 4.1 New host-side module — `src/likedbg/modules.py` (deep, one responsibility)
The build/load seam, mirroring 2a's `guest.py`/`exploit.py` split:
- `build_module(container, *, src_dir, kernel_root, env, out_dir, image) -> Path` — runs the out-of-tree
  `make` in a kbuilder container and copies the resulting `.ko` to `out_dir`; returns the `.ko` path.
- `module_name(ko: Path) -> str` — the loadable module name, read authoritatively from the `.ko`'s
  `.modinfo` (`modinfo -F name`, run in a container), falling back to the filename stem with `-`→`_`
  (the kernel's normalization). Used for `rmmod`/`lsmod`.
- `load(endpoint, ko, args, *, reload, force_unload=False, client=guest) -> GuestResult` — deliver (in
  place if under the share, else `scp`) then `insmod <remote> <args>`. When `reload` and the module is
  already loaded, `rmmod` first; if that returns **EBUSY** (refcount > 0), raise `ModuleError` with the
  refcount and do **not** `insmod` a second copy on top (leaving the old module loaded) — unless
  `force_unload`, which retries `rmmod -f`.
- `unload(endpoint, name, *, force=False, client=guest) -> GuestResult` — `rmmod [-f] <name>`.
- `ModuleError(LikeDbgError)` — build failure, unreachable guest, missing `.ko`, insmod rejection.

### 4.2 New pipeline stage — `ModuleBuildStage`
Runs **after `BuildStage` / before `DebuggeeStage`** in both `build_pipeline` and `build_use_pipeline`
(the built tree is present in the volume in both). For each `settings.build.custom_modules` entry:
- resolve the workspace-relative source dir (already `_reject_unsafe_path`-validated);
- if it is a prebuilt `.ko`, copy it to the share; else `build_module(...)`;
- copy the `.ko` into `workspace/<share_dir>/modules/` (creating it).
`should_skip` returns `True` when `custom_modules` is empty (zero cost when unused). Reads
`ctx.build_label` / the build manifest's `kernel_root` and the effective `share_dir`.

### 4.3 Build container (`modules.build_module`)
kbuilder image (`like_kbuilder_arm64:latest`, the clang-universal cross image), mounts:
- the kernel tree **read-only** at `/ksrc`: volume `likedbg_ksrc:/ksrc:ro` (volume mode) or
  `artifacts/ksrc/<label>` bind (Linux). **Confirmed (2026-07-06):** an out-of-tree `make M=` against a
  RO-mounted, fully-built tree succeeds — it only reads KDIR (scripts/, `Module.symvers`) and writes solely
  into the module dir. RO is therefore both sufficient AND required for cache integrity (a RW mount would
  risk the module build mutating the cached kernel tree and changing its hash).
- the module source dir **read-write at a fixed container path** (`-v <modsrc>:/mod:rw`), NOT an
  identical-path bind. **Confirmed (2026-07-06):** identical-path binds of a workspace subdir do not
  reliably surface under colima (the container saw an empty path); a fixed mount point works.
Command: `make -C /ksrc/<label> M=/mod modules <ARCH=..> <LLVM=1|CROSS_COMPILE=..> -j$(nproc)` (from
`recipe.env()`). `make M=` writes `.o`/`.ko`/`.mod*`/`Module.symvers`/`modules.order` **into the module
dir** (`/mod`, which is the host source dir via the bind) — the `.ko` is then copied to the share; the
build litter stays in the source dir (gitignored; `input_hash` already ignores it). One container run per
`custom_modules` entry (module builds are seconds; the typical case is 1–2 modules).

### 4.4 `--insmod` command (`cli.cmd_insmod` → `modules` + `guest`)
`start_kgdb --insmod [PATH] [--args "k=v …"]`, pure host, dispatched early (before Docker/tmux), targets
`artifacts/runs/latest` — same shape as `--analyze-crash` / `--run`.
- `PATH` = a module **source dir** → build if the source's `input_hash` differs from the staged `.ko`'s
  recorded hash (or the kernel label changed), else reuse; or a
  **`.ko`** → use directly. **No `PATH`** → every configured `custom_modules` entry.
- Reads the run's `guest` block (2a) for the endpoint + the rootfs manifest for the key.
- Delivers to `/mnt/exploit/modules/` (in place if under the share, else `scp`), then `load(reload=True)`.
- Prints the load result and **the `.ko`'s guest path** (for `add-symbol-file`/`lx-symbols`), plus a
  `dmesg` tail on failure.
- **Reload on a busy module:** default surfaces the `rmmod` EBUSY (refcount) and aborts, leaving the old
  module loaded — never `insmod`s a duplicate. `--force-unload` opts into `rmmod -f` (a debug-sandbox
  escape hatch that can itself panic, and needs `CONFIG_MODULE_FORCE_UNLOAD` — §4.6 enables it in the
  exploit profile).
- `--rmmod NAME` → `unload` (with `--force-unload` → `rmmod -f`).

### 4.5 Config
`build.custom_modules: tuple[str, ...]` (already defined + validated in B1) becomes live: consumed by
`ModuleBuildStage` and as the default set for `--insmod` with no `PATH`. No new config keys.
`configs/default.toml` keeps `custom_modules = []` (opt-in).

The `exploit-dev` debug profile gains a Kconfig fragment enabling **`CONFIG_MODULE_FORCE_UNLOAD=y`** (with
`CONFIG_MODULE_UNLOAD=y`) so `--force-unload` works on the default kernel; without it, `--force-unload`
surfaces "kernel lacks `CONFIG_MODULE_FORCE_UNLOAD`". (`CONFIG_MODULE_SIG` stays unset — unsigned loads.)
This changes the `exploit-dev` `.config` → a **one-time kernel rebuild** for exploit-dev users (the live
gate does it); a `[[expect]] CONFIG_MODULE_FORCE_UNLOAD=y` assertion is added to the profile.

No `run.json` "modules" block is needed: `--insmod` with no `PATH` reads `custom_modules` from config, and
`--rmmod` takes an explicit name — both derive from config + the staged `.ko`s (and their sidecar hashes)
in `exploit/modules/`.

### 4.6 Seeds (`modules/`, committed; build litter gitignored)
- `modules/README.md` — documents the out-of-tree flow + the loop.
- `modules/template/` — a minimal `obj-m` skeleton: `Makefile` (`obj-m += hello.o` + the standard
  `make -C $(KDIR) M=$(PWD) modules` convenience target) + `hello.c` (a `printk` on init/exit).
- `modules/lk01/` — an **original, minimal, deliberately-vulnerable** char/ioctl driver (`obj-m`, GPL):
  a `/dev/lk01` char device whose `ioctl` does an unchecked `copy_from_user` of a user-controlled length
  into a fixed-size buffer (a textbook overflow). NOT a port of Pawnyable's LK01 (avoids licensing);
  original code we control. Plus `expl.c` — a **crash-triggering PoC**: open `/dev/lk01`, fire the
  vulnerable `ioctl` with an oversized length → overflow → kernel panic. Its job is to validate the whole
  loop end-to-end (`--insmod` the driver → `--run` the PoC → 2a delivers → panic → B3 auto-produces
  `crash.json`/`crash.md`), NOT to be a full LPE. Documented as the starting point for a real exploit.
  **2b builds only the `.ko`** (§2 non-goal): `expl.c` is a userspace binary, so `modules/lk01/` ships a
  README one-liner + a `Makefile` target to cross-compile it **statically** for the guest (the kbuilder
  image's clang cross). The demo is thus `--insmod ./modules/lk01` → compile the PoC per the one-liner →
  `--run ./exploit/lk01_expl` — one manual compile step; a turnkey userspace-exploit build is a possible
  later exploit-loop nicety, not 2b.
- Legacy `examples/c_kmod/` (in-tree `obj-$(CONFIG_*)` + Kconfig) → moved to `examples/legacy-intree/`
  with a note; not built by this mechanism.
- `.gitignore`: ignore module build litter (`modules/**/*.ko`, `*.o`, `*.mod*`, `.*.cmd`, `Module.symvers`,
  `modules.order`) but keep the sources + READMEs.

## 5. Data flow (edit → build → load → exploit → observe)

1. `custom_modules = ["modules/lk01"]`. `start_kgdb` boots; `ModuleBuildStage` builds `lk01.ko` against
   `/ksrc/<label>` and stages it at `exploit/modules/lk01.ko` (live at `/mnt/exploit/modules/lk01.ko`).
2. `continue` in gdb → guest to userspace. Arm gdb for the load: breakpoint `do_init_module` (or source
   the kernel's `lx-symbols` from `/ksrc/<label>/scripts/gdb`).
3. `start_kgdb --insmod ./modules/lk01` → (rebuilds if you edited the driver) → delivers → `insmod` → gdb
   catches `lk01_init` as the module maps → step through the vuln's setup.
4. `start_kgdb --run ./exploit/lk01_expl` (2a) → runs the exploit against the loaded module; if it faults
   the kernel, Branch 1's crash breakpoints trap → `--run` prints the `crash.md` path (crash-durable).
5. Edit the driver or the exploit → back to step 3/4, **no reboot, no kernel rebuild**.

## 6. `--insmod` semantics + error handling

`start_kgdb --insmod <path|—> [--args "…"]` / `--rmmod <name>`, pure host, dispatched early. Targets
`artifacts/runs/latest`. Build-if-stale (source `input_hash` vs the hash recorded beside the staged `.ko`)
or passthrough (`.ko`). Delivery
in-place under the share else `scp`. `insmod` under `/mnt/exploit/modules`; reload = `rmmod` then `insmod`.

**Error handling:**
- No live run / `run.json` missing → clear error (like `--run`).
- Module build fails (`make` non-zero) → `ModuleError` with the build-log tail + the source path.
- Guest unreachable (`wait_ready` timeout) → same remedy as `--run` (booted + continued past `start_kernel`?).
- `insmod` rejected (vermagic mismatch / bad ELF / `-EEXIST`) → surface the guest `dmesg` tail + a hint
  (vermagic mismatch: rebuild the kernel to match, or build from source against this kernel — a foreign
  `.ko` is out of scope, §2/2c; already-loaded → `--insmod` reloads / `--rmmod` first).
- Reload where `rmmod` returns **EBUSY** (refcount > 0) → `ModuleError` naming the refcount; old module
  left loaded, no duplicate `insmod`. Remedy: close its users / restart the session, or `--force-unload`
  (needs `CONFIG_MODULE_FORCE_UNLOAD`).
- `--insmod` with no `PATH` and empty `custom_modules` → friendly "nothing to load; set `custom_modules`
  or pass a path".
- `.ko` not found / not a module → error naming the path.
- The run's config had `guest_net=false` → `--insmod` errors with the 2a remedy (no guest endpoint).

## 7. Testing + live gate

- **Unit:** `build_module` builds the correct kbuilder `docker run … make -C /ksrc/<label> M=<src> modules
  ARCH=… LLVM=1` command (fake `ContainerService`) and copies the `.ko` out; `module_name` resolves via
  `modinfo` with a `-`→`_` stem fallback; the `input_hash` staleness check (rebuild vs reuse) and prebuilt
  `.ko` passthrough; `load`/`unload` build the right `insmod`/`rmmod`/`rmmod-then-insmod` (+ EBUSY abort,
  `--force-unload` → `rmmod -f`) over a fake guest client;
  `--insmod` resolves endpoint/key, decides build-vs-passthrough and in-place-vs-`scp`, and reloads;
  `ModuleBuildStage` builds + stages each `custom_modules` entry and `should_skip`s when empty; prebuilt
  `.ko` passthrough; the config slot is consumed. Fakes mirror the 2a `guest.py` test doubles.
- **Live gate (both arches):** `custom_modules=["modules/lk01"]` → boot → `ModuleBuildStage` produced
  `exploit/modules/lk01.ko` (vermagic matches) → `continue` → `--insmod ./modules/lk01` →
  `lsmod`/`dmesg` shows it loaded → edit the driver → `--insmod` reloads (`rmmod`+`insmod`) →
  `--run ./exploit/lk01_expl` exploits it → (if it panics) crash report auto-produced. arm64 native +
  x86_64 in-container. Record a transcript under `docs/superpowers/notes/`.

## 8. Docs

- **ADR-0009** — out-of-tree `obj-m` build model (vs legacy in-tree injection); load-on-command (vs
  auto-`insmod`); `.ko` staged in the Guest share; prebuilt-`.ko` passthrough.
- **CONTEXT.md** — add **Custom module** and **Module build**.

## 9. Risks (for the live gate)

- **RO kernel tree + `make M=`**: ✅ CONFIRMED (2026-07-06) — an out-of-tree build against a RO-mounted,
  fully-built `/ksrc` succeeds (writes only into the module dir). Closed as a risk; RO is required for
  cache integrity. Re-verify only if the kernel version/config changes materially.
- **Toolchain/vermagic match**: the `.ko` must be built with the exact `ARCH`+compiler as the kernel or
  `insmod` rejects it — the shared `recipe.env()` guards this. ✅ Confirmed arm64 (vermagic
  `6.6.30 SMP preempt mod_unload aarch64`); verify x86_64 at the live gate.
- **9p write of build litter** under the colima share (same class as 2a's console.raw/crash-drop).
- **x86_64 in-container**: the kbuilder build container + the RW module-source mount under the colima
  share; the `.ko` copied into the published Guest share.
- **Module name vs `.ko` filename** (`-`→`_`) for a correct `rmmod`/reload.
