# Custom modules: out-of-tree `obj-m` build, staged in the Guest share, loaded on command

The exploit deploy/run loop needs a **vulnerable kernel module** to target. `build.custom_modules` (2b,
`feat/custom-modules`) turns the B1 schema slot into a real build-and-load path. We build each entry
**out-of-tree** — `make -C /ksrc/<label> M=<modsrc> modules` against the already-built kernel tree in the
`likedbg_ksrc` volume, using the **same `recipe.env()`** (`ARCH`, `LLVM=1`) as the kernel build so the
`.ko` vermagic/ABI match. The `.ko` is staged into the 2a **Guest share** (`<share_dir>/modules/` → guest
`/mnt/exploit/modules/`). A boot-time `ModuleBuildStage` builds every configured module; `start_kgdb
--insmod [PATH]` builds-if-stale (or passes a prebuilt `.ko` through), delivers, and loads on demand
(`rmmod`-then-`insmod` to reload). Loading is **never** automatic at boot.

## Considered Options

- **In-tree injection (the legacy `custom_modules` semantics).** Rejected as the default: copying each
  module dir into the kernel source tree, adding a Kconfig entry, enabling `CONFIG_*`, and building it as
  part of `make all` ties every module edit to a full kernel rebuild (minutes) and cache invalidation, and
  offers no live reload — it breaks the fast edit→load→exploit loop. Out-of-tree builds a `.ko` in seconds
  against the existing tree with no kernel rebuild. Built-in (`=y`) vuln code that genuinely must live in
  `vmlinux` remains expressible via `patch_dirs`/`extra_fragments`, so nothing essential is lost. The
  legacy in-tree examples move to `examples/legacy-intree/` for reference.
- **Auto-`insmod` at boot (a rootfs boot hook).** Rejected: the module's `init` would run before the
  operator can arm gdb. For exploitation you `continue` past `start_kernel`, breakpoint `do_init_module`
  (or source the kernel's `lx-symbols`) **while the module is unloaded**, then `insmod` — that is the only
  window in which gdb can catch the module's `init` as it maps. Load-on-command preserves that window and
  is simpler (no guest-side unit, load manifest, or ordering).
- **Bake the `.ko` into the rootfs.** Rejected: it ties module identity to the rootfs cache key and forces
  a rootfs rebuild per module edit. The 2a Guest share already surfaces a host file at `/mnt/exploit`
  live, crash-durably, with no rebake — the natural carrier.
- **A separate module-signing / signed-`insmod` path.** Rejected as unnecessary: the built kernel has
  `CONFIG_MODULE_SIG` unset, so unsigned `insmod` is accepted; adding signing is scope we do not need.
- **Fold module loading into `--run`.** Rejected: `--run` executes a userspace exploit binary; loading a
  module is distinct behavior (`insmod`/`rmmod`, module name resolution, reload) and deserves its own
  `--insmod`/`--rmmod` verbs. They compose in the loop (`--insmod` the driver, then `--run` the exploit).

## Consequences

- Module builds reuse the kbuilder image + `recipe.env()`; the built kernel tree must remain present in
  the volume (it does — nothing deletes it post-build). The build container mounts the tree read-only and
  the module source read-write; `make M=` writes `.o`/`.ko` beside the source (`input_hash` already
  ignores those, and the seed dirs gitignore build litter).
- `custom_modules` is **not** added to the kernel `BuildRecipe` cache key — a module edit must not
  invalidate the kernel build. The module stage rebuilds a `.ko` when its source is newer or the kernel
  `label` changed.
- Symbol autoload for module debugging (`lx-symbols` / auto `add-symbol-file`) is **B4**; 2b only
  guarantees a known `.ko` path and prints it on load.
