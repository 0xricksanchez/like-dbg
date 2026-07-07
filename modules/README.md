# modules/ — out-of-tree custom kernel modules

This is where **custom kernel modules** (a `build.custom_modules` entry) live: each subdirectory is
a self-contained out-of-tree module source tree — an `obj-m` `Makefile` plus its `.c` sources — built
against the already-built kernel tree (`make -C /ksrc/<label> M=<modsrc> modules`) and loaded into a
live guest on command. See `docs/adr/0009-out-of-tree-custom-modules-load-on-command.md` for the
full design and rationale.

This replaces the old **in-tree** module injection (`examples/legacy-intree/`, pre-2b): copying a
module into the kernel source tree, wiring a Kconfig entry, and rebuilding the whole kernel to pick
it up. Out-of-tree modules build in seconds against the existing tree, with no kernel rebuild and no
cache invalidation from a module edit.

## Convention: directory name == `.ko` name

The staged `.ko` is always named after the module's **directory**, regardless of the `obj-m` object
name in its Makefile — e.g. a dir `modules/bar/` whose Makefile says `obj-m += foo.o` still gets
staged as `bar.ko` (the build's `foo.ko` is renamed on staging). This is safe: a module's loadable
name is its *internal* name (`modinfo -F name`), independent of the `.ko` filename — `insmod`
resolves it regardless of what the file is called. Keep new modules named consistently
(`modules/lk01/` -> `obj-m += lk01.o` -> `lk01.ko`) anyway; it's the tidy default and keeps the
directory-name canonicalization a no-op rename.

## `custom_modules`

Configure modules to build automatically at boot time (staged into the Guest share, never
auto-loaded):

```toml
[build]
custom_modules = ["modules/lk01"]
```

Each entry is a path (relative to the workspace root) to either a module source directory (built
out-of-tree) or a prebuilt `.ko` (vermagic must match the like-dbg-built kernel — passed through
as-is). A boot-time stage builds every configured entry against the session's kernel tree once the
kernel build has run.

## Loading on demand: `--insmod` / `--rmmod` / `--force-unload`

Loading a module is never automatic — it happens on command, once you've armed gdb (e.g.
breakpointed `do_init_module`) so you can catch the module's `init` as it loads:

```bash
# build-if-stale + load (path optional — defaults to every configured custom_modules entry):
uv run ./start_kgdb --insmod ./modules/lk01

# unload by module name:
uv run ./start_kgdb --rmmod lk01

# force an unload even if the device looks busy:
uv run ./start_kgdb --rmmod lk01 --force-unload
```

`--insmod` reloads (`rmmod`-then-`insmod`) if the module is already loaded. The `.ko` is staged into
the Guest share (`<share_dir>/modules/` -> guest `/mnt/exploit/modules/`), and its path is printed
so you can `add-symbol-file` it in gdb.

**Compiler match matters:** `--use` / `--insmod` build the module with the compiler from your
*current* config (`build.compiler`) — it must still match the compiler the reused kernel was built
with (clang vs. gcc), or `insmod` will reject the `.ko` on a vermagic/ABI mismatch. If you switch
`build.compiler` between sessions, rebuild the kernel (or point at a kernel built with the same
compiler) before loading modules against it.

## `modules/template/` — start a new module

A minimal `obj-m` skeleton (`hello.c` + `Makefile`) that loads and unloads cleanly, logging via
`pr_info`. Copy the directory, rename it (and `obj-m`) to your module's name, and build out from
there.

## `modules/lk01/` — the LK01 demo

An original, deliberately vulnerable `/dev/lk01` misc char device (an unchecked
`copy_from_user` stack overflow) plus a crash-triggering PoC, wired for the full
build -> insmod -> exploit loop. See `modules/lk01/README.md` for the bug, the loop, and the PoC
cross-compile one-liner.
