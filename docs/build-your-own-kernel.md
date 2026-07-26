# Building and debugging your own kernel

This is the default LIKE-DBG workflow: pick a kernel version, build it once, boot it under QEMU,
and attach GDB. It is the daily driver for studying the kernel and developing exploits against a
kernel you control.

If you instead have a ready-made CTF or challenge kernel to debug, see
[ctf-foreign-kernel.md](ctf-foreign-kernel.md).

## Before you start

Install the host requirements and dependencies as shown in the [README](../README.md#quickstart)
(`uv sync`), then start the project tmux server:

```sh
tmux -L likedbg -f .tmux.conf new -s LIKE-DBG
```

Run everything below inside that session.

## 1. Choose what to build

Three things decide what gets built: the kernel version, the compiler, and the debug profile.
They live in the TOML config (see [configuration.md](configuration.md) for the full reference);
this guide shows the parts you touch most.

Set the version under `[source]` in `configs/default.toml` (or a personal
`configs/local.toml`):

```toml
[source]
kind = "mmp"      # mmp | tag | commit (labels the intent)
value = "6.6.30"  # a release, a git tag, or a commit hash

[build]
compiler = "clang"  # clang | gcc
```

The `value` decides where the source comes from: a `major.minor.patch` release (for example
`6.6.30`) is fetched from the kernel.org CDN, while a tag (for example `v6.9-rc1`) or a commit
hash is fetched as a git.kernel.org snapshot.

The debug profile decides the kernel's build-time character. The default is `exploit-dev` (no
KASLR, debug info, kallsyms, module force-unload), which is what you want for most exploit work.
Pick another with `--profile` or the `[debugging]` section:

```sh
uv run ./start_kgdb --profile hardened          # mitigations compiled in
uv run ./start_kgdb --profile exploit-dev,kasan  # base plus an add-on
```

Inspect the fully resolved config, including profiles, without touching Docker:

```sh
uv run ./start_kgdb --explain-config
uv run ./start_kgdb --explain-config json
```

### Customize the build

Beyond version, compiler, and profile, two extension points let you reach further without writing
a new profile.

**Add a custom kconfig fragment.** A fragment is a partial `.config`: plain kconfig lines, for
example `CONFIG_FOO=y` or `# CONFIG_BAR is not set`. Create one under `configs/fragments/`:

```sh
mkdir -p configs/fragments
cat > configs/fragments/my-feature.config <<'EOF'
CONFIG_FOO=y
# CONFIG_BAR is not set
EOF
```

Then point `[build] extra_fragments` at it, in `configs/local.toml` or a scenario:

```toml
[build]
extra_fragments = ["configs/fragments/my-feature.config"]
```

Every `extra_fragments` path must live under `configs/fragments/`; a path outside that tree is a
config error. Fragments are applied over `make defconfig` via `scripts/kconfig/merge_config.sh -m`,
then `make olddefconfig` resolves newly-enabled dependencies. Merge order is the active profiles'
fragments first, then `extra_fragments` last, so your fragment wins on a conflicting symbol.
Verify what actually applied without rebuilding:

```sh
uv run ./start_kgdb --explain-config
```

which lists profile fragments, extra fragments, and patches for the resolved config.

**Patch the kernel source.** `[build] patch_dirs` applies patch files to the freshly-untarred,
pristine source before the build starts. Put personal patches under a workspace-root `patches/`
directory (gitignored):

```sh
mkdir -p patches/my-fix
# drop 0001-thing.patch (or a .diff) into patches/my-fix/
```

```toml
[build]
patch_dirs = ["patches/my-fix"]
```

Only files ending `.patch` or `.diff` are applied, found recursively; directories apply in the
list order given, and files within a directory apply in alphabetical order. Each patch is applied
with `patch -p1 -i <file>`, so it must apply cleanly at `-p1` against a stock upstream tree.
Changing `patch_dirs` changes the source identity (patches are part of the cache key), so it
produces a new shared source tree, which `--list`/`--clean` account for separately.

**Define a debug profile.** A profile bundles fragments plus post-build `.config` checks, warnings,
implied profiles, and runtime defaults under one name, so `--profile <name>` captures a whole
debugging intent instead of a loose list of fragments. The shipped profiles live in
`configs/profiles/` (`exploit-dev`, `hardened`, `crash-debug`, `kasan`, `ubsan`, ...); read those
for real examples. `exploit-dev`, the default, is a `base` profile:

```toml
# configs/profiles/exploit-dev.toml (excerpt)
name = "exploit-dev"
kind = "base"                         # exactly one base is active; base profiles set KASLR policy
description = "Convenient exploit research baseline."
fragments = ["configs/fragments/no-kaslr.config", "configs/fragments/debug.config"]

[[expect]]                            # verified against the built .config
symbol = "CONFIG_RANDOMIZE_BASE"
value = "n"
severity = "hard"                     # hard aborts the boot; soft only warns
```

To add your own, drop a TOML file in `configs/profiles/`. A minimal add-on (add-ons stack on the
base and may pull in others):

```toml
# configs/profiles/my-debug.toml
name = "my-debug"
kind = "addon"
description = "My extra debug knobs."
implies = ["crash-debug"]                                  # optional: pull in another profile
fragments = ["configs/fragments/profiles/my-debug.config"]

[[expect]]
symbol = "CONFIG_PROVE_LOCKING"
value = "y"
severity = "soft"

[[warning]]                                                # optional advisory shown at resolve time
message = "my-debug is slow under TCG."
accel = ["tcg"]

[runtime_defaults.debuggee]                                # optional [debuggee] defaults this profile sets
smap = false
```

Then select it (comma-separated, one base plus any add-ons) and inspect the result:

```sh
uv run ./start_kgdb --profile exploit-dev,my-debug --explain-config
```

## 2. Build and boot

```sh
uv run ./start_kgdb
```

This downloads the source, configures and compiles the kernel, builds a matching root
filesystem, boots the guest under QEMU, and attaches the debugger. The first build is slow
(fetching and compiling a kernel); it is cached afterward, so later runs that reuse the same
configuration start in seconds. After a fresh build, LIKE-DBG verifies the resulting `.config`
against the profile's expectations and refuses to boot if a hard expectation failed.

The debugger lands at `start_kernel` with full symbols. The two panes are QEMU (the Debuggee) and
GDB (the Debugger). The generated root filesystem has two accounts so you can work from either
side: `root` with no password, and `user` with password `user`.

## 3. Debug

Kernel runs default to pwndbg, which brings a kernel command set for introspection: KASLR base,
slab, `current`, task and module walking, and symbol lookup (`kbase`, `slab`, `kcurrent`,
`ktask`, `klookup`, `kmod`, `kallsyms`). To use GEF instead, add `[debugger] ext = "gef"` to
`configs/local.toml`.

For a scenario-tailored debugging session, drop GDB commands into `io/scripts/gdb_script`; they
are sourced at attach time.

If you restart the Debuggee (the `C-b B` binding in the shipped `.tmux.conf`, or
`uv run ./start_kgdb --restart-debuggee`), QEMU relaunches but GDB loses the old target. Run
`likedbg-reconnect` in the GDB pane to reattach to the new gdbstub and resume to `start_kernel`.
Do not use `target remote :1234` from inside the Debugger container: `localhost` is the
container, not the host QEMU process. A raw manual attach uses `target remote
host.docker.internal:1234`.

To start a fresh native QEMU/GDB pair after changing the scenario or build inputs, run
`uv run ./start_kgdb --re-run`. It closes LIKE-DBG's existing Debugger and Debuggee panes, keeps
the host pane, and reuses the original scenario, profile, and (when chosen) `--force-rebuild`.

## 4. Iterate on an exploit

The inner loop is edit, deliver, run, crash, root-cause, repeat. Put your exploit under
`exploit/`, which is live-shared into the guest at `/mnt/exploit`, then run it against the live
session:

```sh
uv run ./start_kgdb --run ./exploit/poc.c          # a flag-less .c is auto-compiled, then run
uv run ./start_kgdb --run ./exploit/poc            # a prebuilt binary is delivered as-is
uv run ./start_kgdb --run ./exploit/poc --args "1 2"
uv run ./start_kgdb --upload ./exploit/poc.c       # deliver over the serial console
```

A single flag-less `.c` is auto-compiled static-musl to the target architecture; anything else
(C++, multiple files, custom flags, assembly, or a glibc-semantics exploit) is delivered
unchanged, so you cross-compile it yourself. The full boundary and the escape hatch are in
[exploit/README.md](../exploit/README.md).

The exploit's stdout, stderr, and any crash report land in the run directory. When the exploit
faults the kernel, crash intelligence traps GDB at the fault, captures a symbolized backtrace,
and writes `crash.json` and `crash.md`. Regenerate a report from a past run offline:

```sh
uv run ./start_kgdb --analyze-crash            # the latest run
uv run ./start_kgdb --analyze-crash <run-id>
```

Every session records a timestamped `artifacts/runs/<id>/` (resolved settings, host profile,
command records, logs, and pane transcripts); `artifacts/runs/latest` points at the most recent
one.

## 5. Load a custom module

To debug an out-of-tree driver (for example a vulnerable module you target from an exploit),
build it against the running kernel and load it on command:

```sh
uv run ./start_kgdb --insmod ./modules/lk01   # build-if-stale, then load
uv run ./start_kgdb --rmmod lk01
```

Modules are never auto-loaded at boot, so you can arm GDB (for example breakpoint the module's
`init`) before it loads. The module's symbols auto-load in GDB at your next stop. The full
lifecycle, including reload-on-edit and the compiler-match requirement, is in
[modules/README.md](../modules/README.md). `modules/lk01/` is a worked example with a
deliberately vulnerable driver and a crash PoC.

## Managing the build cache

A build is keyed by its configuration, so an identical configuration is never rebuilt. Manage the
cache with:

```sh
uv run ./start_kgdb --list                     # cached kernel builds and rootfs images
uv run ./start_kgdb --use <build-label>        # reuse a cached build (builds the rootfs if absent)
uv run ./start_kgdb --use <build-label> --rootfs <rootfs-label>
uv run ./start_kgdb --clean <label>            # remove one cached artifact
uv run ./start_kgdb --clean-all                # clear the cache
uv run ./start_kgdb --prune [SIZE]             # evict least-recently-used builds to fit SIZE (or [cache] max_size)
uv run ./start_kgdb --force-rebuild            # discard this configuration's cached kernel build and build it again
```

`--force-rebuild` carries the same meaning on a foreign scenario, where there is no cached build to
discard: it ignores the recorded inputs and redoes the vmlinux extraction and the initramfs repack
(see [ctf-foreign-kernel.md](ctf-foreign-kernel.md#deliver-an-exploit)). Neither form touches the
exploit-compile cache volume; `--clean-all` is what clears that.

Kernel source trees are shared across builds with the same (version, patches): `--list` shows
each source with a refcount of the builds referencing it plus each build's last-used time, and
`--clean`/`--clean-all` auto-remove a source once its last referencing build is cleaned.

To bound total cache disk, set `[cache] max_size` (see [configuration.md](configuration.md#cache)):
when set, an automatic least-recently-used sweep runs after each new build, keeping the cache under
the cap (the build you just made is never evicted). `--prune [SIZE]` does the same on demand.

## Limitations

- **Architectures:** x86_64 and arm64 only.
- **Kernel versions:** the build chain targets recent kernels; very old trees may not configure
  or compile cleanly.
- **Compiler match for module reuse:** `--insmod` builds a module with your current
  `[build] compiler`, which must match the compiler the reused kernel was built with (clang
  versus gcc), or `insmod` rejects the `.ko` on a vermagic mismatch. Rebuild the kernel if you
  switch compilers between sessions.
- **Host backend differs by platform:** Apple Silicon boots arm64 guests with native HVF; an
  x86_64 guest on a Mac and a Linux host without KVM run under in-container TCG (slower); a Linux
  host with KVM uses it. The backend is auto-detected and recorded in the run's `host.json`.
- **Pane transcripts are not byte-perfect.** The Debuggee and Debugger pane logs are operator
  transcripts with a small gap at each restart. For byte-exact serial output, use the run's
  `logs/console.raw`, which is teed straight from QEMU.
