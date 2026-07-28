# Configuration reference

LIKE-DBG is configured through a layered TOML stack and a set of named debug profiles. This
document is the reference for both, plus every knob you can set.

## The config stack

Configuration is merged from several files, lowest precedence first:

| File | Role |
|---|---|
| `configs/default.toml` | Tracked project defaults. Edit for repo-wide changes. |
| `configs/local.toml` | Personal overrides, gitignored. Create from `configs/local.example.toml`. |
| `configs/scenarios/<name>.toml` | Named scenario configs, loaded with `-c <name>` or `-c <path>`. |

CLI flags win over every file. So a value set on the command line beats a scenario, which beats
your local overrides, which beat the project defaults.

The everyday mental model is three layers: project defaults, your local or scenario overrides,
and the CLI. Internally the loader tracks six layers (built-in, default, profile, local,
scenario, CLI) and records which one won for each key; that provenance is written to each run's
`settings.effective.json` for inspection but does not change how you set values.

### Overriding on the command line

```sh
uv run ./start_kgdb --profile hardened          # select a debug profile
uv run ./start_kgdb -c lk01                      # load configs/scenarios/lk01.toml
uv run ./start_kgdb -c /path/to/my.toml          # or an explicit path
```

### Inspecting the resolved config

`--explain-config` resolves the full stack and profiles without touching Docker, tmux, or run
directories:

```sh
uv run ./start_kgdb --explain-config
uv run ./start_kgdb --profile kasan --explain-config json
```

## Debug profiles

A debug profile is a named debugging intent. It resolves to kernel config fragments, expected
post-build `.config` checks, optional warnings, and runtime defaults. Profiles answer "what kind
of kernel and debugging experience am I building for?"

| Profile | Kind | Purpose |
|---|---|---|
| `exploit-dev` | base | No KASLR, debug info, kallsyms, module force-unload. The daily-driver default. |
| `hardened` | base | Mitigations compiled in; KASLR, SMEP, SMAP, and KPTI showcasable at runtime. |
| `crash-debug` | add-on | Readable oops and panic triage while keeping a normal-ish kernel. |
| `kasan` | add-on | KASAN memory-bug detection for use-after-free and out-of-bounds research (implies `crash-debug`). |
| `ubsan` | add-on | Lower-cost undefined-behavior detection (implies `crash-debug`). |
| `lockdep` | add-on | Locking and concurrency diagnostics. |
| `kcov-lite` | add-on | Prepares the kernel for later coverage-guided bug finding. |

Rules:

- **Exactly one base profile.** `exploit-dev` and `hardened` are mutually exclusive because they
  make conflicting build-time KASLR decisions. Requesting two base profiles is an error.
- **Add-ons stack** on top of the base, and some pull in others (`kasan` and `ubsan` both imply
  `crash-debug`).
- Select profiles with `--profile` (comma-separated, overrides the config) or the `[general] profiles`
  section:

  ```sh
  uv run ./start_kgdb --profile exploit-dev,kasan
  ```

- **Post-build verification.** After a fresh build, LIKE-DBG checks the resulting `.config`
  against each profile's expectations. A `soft` expectation warns; a `hard` one aborts the boot,
  so a profile that silently did not take is caught before you debug.
- **Custom profiles.** Add a TOML file under `configs/profiles/` to define your own; add-ons may
  declare `implies`, `[[warning]]` blocks, `[[expect]]` checks, and `[runtime_defaults.debuggee]`.
  See [build-your-own-kernel.md](build-your-own-kernel.md#customize-the-build) for a worked
  `exploit-dev` excerpt and a minimal custom-profile example.

## Host-detected settings

Some axes are detected from the host rather than configured, and recorded in each run's
`host.json`:

- **Acceleration** is native HVF on Apple Silicon debugging a same-architecture guest, KVM on a
  Linux host with `/dev/kvm`, and TCG otherwise. Override with `[debuggee] accel`.
- **Storage mode** (whether the kernel source tree is host-visible) is bind on Linux and chosen
  automatically on macOS. Override with `[general] storage`.
- **Network mode** (how the Debugger reaches the gdbstub) is host networking on Linux and
  published ports on macOS. Override with `[debuggee] network`.
- **Debuggee mode** (whether QEMU runs as a host process or inside the debuggee container)
  follows from the host and guest architecture.

`[general] arch = "native"` resolves to the host's architecture; set it to `x86_64` or `arm64`
to cross-build and boot a foreign-architecture guest.

## Running more than one session

Each boot takes over its tmux session under a name that says what it is debugging:
`LIKE-DBG-pawnyable-lk01` for a scenario, `LIKE-DBG-6_6_30-exploit-dev` for a plain run (kernel and
base profile), `LIKE-DBG-6_6_30-a1b2c3d4` for `--use`. Booting the same thing twice adds `-2`. So a
session you left running no longer blocks the next one, and two challenges can sit side by side.

Two guests cannot share a host port, so ports are checked before use:

- A port **you never set** -- the shipped `configs/default.toml` value or the built-in default -- is
  a placeholder. If it is busy the boot takes the next free one and logs
  `port: gdbstub_port 1234 was busy; using 1235`.
- A port **you did set**, in a scenario, `local.toml`, a profile, or on the command line, is an
  instruction: a fixed gdb target, a port-forward, a script. It is used exactly, or the boot stops
  and tells you what is holding it. It is never moved for you.

Only ports a boot actually binds are considered, so a `[foreign]` guest -- which has neither the
gdbstub-side SSH transport nor a share -- contends for nothing.

`--run`, `--upload`, `--insmod` and `--rmmod` act on the run belonging to **the tmux session you
type them in**, so an exploit cannot land in the other guest. Pass `--run-id` to target a specific
run, and outside a LIKE-DBG session they fall back to the most recent run in the workspace.

## Section reference

### `[general]`

| Key | Default | Values and meaning |
|---|---|---|
| `arch` | `native` | `native`, `x86_64`, `arm64`. `native` resolves to the host architecture. |
| `storage` | `auto` | `auto`, `bind`, `volume`. Storage mode: where the kernel source tree lives. |
| `profiles` | `["exploit-dev"]` | The active debug profiles (see above). `--profile` overrides. |
| `workspace_dir` | unset | Override the workspace root. |

### `[source]`

| Key | Default | Values and meaning |
|---|---|---|
| `kind` | `mmp` | `mmp`, `tag`, `commit`. Labels the intent of `value`. |
| `value` | (required) | A release (`6.6.30`, fetched from the kernel.org CDN), or a tag or commit hash (fetched as a git.kernel.org snapshot). |

### `[build]`

| Key | Default | Values and meaning |
|---|---|---|
| `compiler` | `clang` | `clang`, `gcc`. |
| `toolchain` | `auto` | Cross-toolchain selection; `auto` is chosen from compiler and architecture. |
| `rust` | `false` | Enable Rust-for-Linux support. |
| `label_suffix` | empty | Extra tag folded into the build's cache label. |
| `patch_dirs` | empty | Workspace-relative directories of patch files applied before build. |
| `custom_modules` | empty | Workspace-relative out-of-tree module sources or prebuilt `.ko` files, built at boot. See [modules/README.md](../modules/README.md). |
| `extra_fragments` | empty | Extra kconfig fragments (must live under `configs/fragments/`). |
| `ccache` | `true` | Cache compilation via ccache (persistent, capped) for fast rebuilds. |
| `ccache_max_size` | `5G` | Max ccache size (ccache size syntax, e.g. `5G`, `500M`). |

`extra_fragments` entries must live under `configs/fragments/` (a path outside that tree is a
config error); they are merged over `make defconfig` after the active profiles' own fragments, so
an extra fragment wins on a conflicting symbol. `patch_dirs` entries are applied with `patch -p1`
against the pristine, freshly-untarred source, restricted to `.patch`/`.diff` files, in the given
directory order and alphabetically within a directory; the convention is a gitignored
workspace-root `patches/` directory, e.g. `patches/my-fix/0001-thing.patch`. A `patch_dirs` change
produces a new cached source tree, since patches are part of the source cache key. Worked examples
for both live in [build-your-own-kernel.md](build-your-own-kernel.md#customize-the-build).

### `[exploit]`

Settings for the exploit auto-compile, shared by `[foreign] exploit`, `--run` and `--upload`. This
is about building *your exploit*, not the kernel — hence its own section rather than a key in
`[build]`.

| Key | Default | Values and meaning |
|---|---|---|
| `flags` | empty | Extra flags for the exploit auto-compile, e.g. `["-lpthread", "-D_GNU_SOURCE"]`. |

`[exploit] flags` reach a single `zig cc` (gcc-driver) invocation for the one `.c`, so they take
**both** compile-time flags (`-D...`, `-I...`, `-O2`, `-std=...`, `-g`) **and** linker flags
(`-lpthread`, `-lm`, `-L...`, `-Wl,...`). Write each as the full flag with its prefix, one token per
list element (`-lpthread`, not `pthread`; `-D_GNU_SOURCE`, not `_GNU_SOURCE`); a space-separated
option must be two elements or joined, e.g. `["-I", "/path"]` or `["-I/path"]`, not `["-I /path"]`.
LIKE-DBG appends them after the source
(`{arch}-linux-musl-gcc -static <src> {flags} -o <out>`) so libraries resolve in link order;
`-D`/`-I` are position-independent, so they still apply. They are used only when LIKE-DBG compiles a
flag-less single `.c` (via `[foreign] exploit`, `--run`, or `--upload`); a prebuilt binary is passed
through unchanged. musl folds pthread/rt/dl into libc, so most `-l` flags are no-ops, but they are
accepted so a challenge's build line copies over verbatim. **macOS note:** the auto-compile
is reliable on a Linux runtime; on Docker Desktop for macOS, libc-heavy sources (for example
pthread) can intermittently fail to compile (a zig cache quirk in the LinuxKit VM), so on a Mac
prefer a prebuilt binary or simply retry. See
[ctf-foreign-kernel.md](ctf-foreign-kernel.md#deliver-an-exploit).

The exploit compile reuses a persistent zig cache (the `likedbg_zigcache` Docker volume): the first
compile is cold (~20s, building musl once) and every later one is a warm hit (~1–2s), across
sessions. `start_kgdb --clean-all` deletes that volume to force a cold rebuild.

### `[cache]`

| Key | Default | Values and meaning |
|---|---|---|
| `max_size` | (unset) | Cache size cap for auto-eviction (e.g. `50G`, `500M`). Unset means no limit. Explicit `--prune` is always available. |

### `[rootfs]`

| Key | Default | Values and meaning |
|---|---|---|
| `distribution` | `bookworm` | Debian release the root filesystem is based on. |
| `hostname` | `LIKE-DBG` | Guest hostname. |

### `[debuggee]`

| Key | Default | Values and meaning |
|---|---|---|
| `memory_mib` | `1024` | Guest RAM in MiB. |
| `smp` | `1` | Guest CPU count. |
| `accel` | `auto` | `auto`, `kvm`, `hvf`, `tcg`. Overrides host-detected acceleration. |
| `network` | `auto` | `auto`, `host`, `published`. How the Debugger reaches the gdbstub. |
| `gdbstub` | `true` | Expose the QEMU gdbstub. |
| `gdbstub_port` | `1234` | gdbstub TCP port. Moved if busy *unless you set it* -- see [Running more than one session](#running-more-than-one-session). |
| `kaslr` | `false` | Enable KASLR at runtime (only if the built kernel supports it). |
| `smep` | `true` | Enable SMEP at runtime (x86_64 only). |
| `smap` | `true` | Enable SMAP at runtime (x86_64 only). |
| `kpti` | `true` | Enable KPTI at runtime (`pti=on`/`nopti` on x86_64, `kpti=off` on arm64). |
| `fgkaslr` | `true` | Enable FG-KASLR at runtime (x86_64 only; `false` emits `nofgkaslr`). For kernels built with the out-of-tree FG-KASLR patchset or CTF kernels that ship it. |
| `mitigations` | unset | Tri-state. `false` emits `mitigations=off`; `true` forces `mitigations=auto`; unset leaves the kernel default. |
| `slab_merge` | unset | Tri-state. `false` emits `slab_nomerge`; `true` emits `slab_merge`; unset leaves the kernel default. |
| `init_on_alloc` | unset | Tri-state `init_on_alloc=1/0`; unset leaves the kernel default. |
| `init_on_free` | unset | Tri-state `init_on_free=1/0`; unset leaves the kernel default. |
| `randomize_kstack_offset` | unset | Tri-state `randomize_kstack_offset=on/off`; unset leaves the kernel default. |
| `hardened_usercopy` | unset | Tri-state `hardened_usercopy=on/off`; unset leaves the kernel default. |
| `panic` | `halt` | `halt` (stay stopped), `reboot`, or another value for a timed reboot. |
| `capture_console` | `true` | Tee the guest serial console to `logs/console.raw`. |
| `ssh_port` | `2222` | Host-side SSH port forwarded into the guest. Same rule as `gdbstub_port`. |
| `share_dir` | `exploit` | Host directory shared into the guest at `/mnt/exploit`. |
| `guest_net` | `true` | Enable guest networking (the SSH transport for `--run` and `--insmod`). |
| `share` | `true` | Enable the 9p live share. |

LIKE-DBG validates the mitigation toggles at config-resolution time and injects the matching kernel
command-line arguments at boot. Two principles govern them:

- **The tool never silently changes the guest.** The tri-state hints (`mitigations`, `slab_merge`,
  `init_on_alloc`, `init_on_free`, `randomize_kstack_offset`, `hardened_usercopy`) default to *unset*
  and emit no boot argument, so a default run's kernel command line is identical to one built without
  these knobs. A knob only ever reaches the guest when you explicitly set it, in `local.toml`, a
  scenario, or on the CLI. This is the same "you tweak it yourself" stance the tool takes toward
  sysctls, which it does not touch at all.
- **An impossible request fails fast, symmetrically.** An *explicit* request to enable a mitigation
  the kernel or architecture cannot provide is a hard error, not a silent no-op. Two checks apply:
    - *Build-time (kconfig) gate.* `kaslr` requires `CONFIG_RANDOMIZE_BASE` and `kpti` requires
      `CONFIG_PAGE_TABLE_ISOLATION` (renamed `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` on 6.9+). If an
      active profile hard-builds the required symbol *off*, enabling the toggle is impossible.
    - *Architecture gate.* `smep`, `smap`, and `fgkaslr` are x86_64-only, so requesting them for an
      arm64 target is impossible; arm64 uses PXN and PAN (enabled by default) and has no
      function-granular KASLR.

For example, `exploit-dev` builds KASLR disabled, so setting `[debuggee] kaslr = true` explicitly
while `exploit-dev` is active fails fast with:

```text
[debuggee] kaslr=on is impossible: active profiles build CONFIG_RANDOMIZE_BASE disabled
```

The fix is to drop the explicit toggle, or switch to a base profile that builds the mitigation in
(e.g. `--profile hardened`). The gate only *validates* the request; it never changes what the kernel
is built with.

A few wiring details. `smep`/`smap` are controlled purely through the x86_64 QEMU `-cpu` feature
flags (`+smep`/`+smap`), not boot arguments: the mainline `nosmep`/`nosmap` params and the
`CONFIG_X86_SMAP` symbol were removed in 5.18/5.19, so disabling one simply drops it from the guest
CPU model. `kpti` is architecture-correct: `pti=on`/`nopti` on x86_64 and `kpti=off` on arm64.
Setting `mitigations = false` is the master switch (`mitigations=off`); on x86_64 the tool then omits
its own `pti=on`, since an explicit `pti=on` would otherwise override the master switch and leave PTI
on. So an explicit `kpti = true` together with `mitigations = false` resolves to PTI off, the master
switch winning. `fgkaslr` only emits `nofgkaslr` (to disable); it is meaningful on kernels actually built with the
out-of-tree FG-KASLR patchset (or CTF kernels that ship it) and is harmlessly ignored elsewhere. Since
`nokaslr` also disables FG-KASLR, a dedicated `fgkaslr = false` matters mainly when base KASLR is on.

For a `[foreign]` kernel, `cmdline` remains verbatim when no mitigation toggle is explicitly set.
You may instead set the `[debuggee]` mitigation toggles in `local.toml`, a scenario, or the CLI;
each explicit setting replaces the corresponding token in the foreign command line. This makes, for
example, `kaslr = false` and `kpti = false` equivalent to `nokaslr nopti`, while preserving all
unrelated challenge boot arguments. `smep` and `smap` already apply through QEMU's CPU model, for
both built and foreign kernels.

### `[debugger]`

| Key | Default | Values and meaning |
|---|---|---|
| `ext` | `pwndbg` | `pwndbg`, `gef`. The GDB extension. |
| `break_on_crash` | `true` | Auto-break GDB at a fault to capture a symbolized backtrace. |
| `crash_breakpoints` | `panic`, `die`, `oops_enter` | Fatal-fault symbols the auto-break halts on immediately. |
| `sanitizer_breakpoints` | (empty) | Opt-in KASAN/UBSAN symbols (e.g. `kasan_report`) to halt on, armed only after the guest reaches userspace via a one-shot gate. Empty by default: a KASAN kernel with the text-poke false positive floods `kasan_report`, so prefer a manual `break kasan_report` right before the exploit. KASAN is captured from the console into `crash.md` regardless. |
| `debuginfod` | `auto` | `auto`, `on`, `off`. Fetch debug info by build-id. `auto` is on for `[foreign]` runs and off for self-built kernels (which already carry their symtab). |
| `debuginfod_urls` | elfutils server | Space-separated debuginfod server URLs. Default is the federated `https://debuginfod.elfutils.org`. |

### `[foreign]`

Present only for a CTF or foreign kernel; its `image` key selects that path. See
[ctf-foreign-kernel.md](ctf-foreign-kernel.md) for the full workflow.

| Key | Meaning |
|---|---|
| `image` | Boot image (`bzImage` or `Image`). Its presence selects the foreign path. |
| `vmlinux` | Optional; provides GDB symbols. |
| `initramfs` | Optional; the challenge root filesystem. |
| `cmdline` | Boot command line, used verbatim. |
| `arch` | Optional architecture override; else auto-detected from the `vmlinux` ELF. |
| `qemu_extra` | Extra QEMU flags, for example a CPU baseline. |
| `exploit` | Optional exploit source or binary, repack-injected at `/exploit`. Repacked only when it (or the initramfs, `[exploit] flags`, or the `like_musl` image) changed; `--force-rebuild` repacks regardless. |
| `net` | Outbound guest networking, default `true`. Adds a user-mode (SLIRP) NIC so the guest reaches the network and the challenge initramfs's boot-time `ifup` wait succeeds instantly instead of stalling ~15s. `false` gives a faithful air-gapped boot (the wait returns). It is a device only, not an SSH control transport — `--run`/`--insmod` still refuse. |
| `net_iface` | Interface name the guest expects, default `eth0`. `ethN` forces the name via `net.ifnames=0`; `enp0sN` pins the NIC's PCI slot so the challenge's kernel names it. Read it off the guest's `Waiting for interface XXX` console line. Other schemes: place the NIC via `qemu_extra` and set `net = false`. |
