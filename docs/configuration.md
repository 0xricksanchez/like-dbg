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
- Select profiles with `--profile` (comma-separated, overrides the config) or the `[debugging]`
  section:

  ```sh
  uv run ./start_kgdb --profile exploit-dev,kasan
  ```

- **Post-build verification.** After a fresh build, LIKE-DBG checks the resulting `.config`
  against each profile's expectations. A `soft` expectation warns; a `hard` one aborts the boot,
  so a profile that silently did not take is caught before you debug.
- **Custom profiles.** Add a TOML file under `configs/profiles/` to define your own; add-ons may
  declare `implies`, `[[warning]]` blocks, `[[expect]]` checks, and `[runtime_defaults.debuggee]`.

## Host-detected settings

Some axes are detected from the host rather than configured, and recorded in each run's
`host.json`:

- **Acceleration** is native HVF on Apple Silicon debugging a same-architecture guest, KVM on a
  Linux host with `/dev/kvm`, and TCG otherwise. Override with `[debuggee] accel`.
- **Storage mode** (whether the kernel source tree is host-visible) is bind on Linux and chosen
  automatically on macOS. Override on macOS with `[general] mac_storage`.
- **Network mode** (how the Debugger reaches the gdbstub) is host networking on Linux and
  published ports on macOS. Override with `[debuggee] network`.
- **Debuggee mode** (whether QEMU runs as a host process or inside the debuggee container)
  follows from the host and guest architecture.

`[general] arch = "native"` resolves to the host's architecture; set it to `x86_64` or `arm64`
to cross-build and boot a foreign-architecture guest.

## Section reference

### `[general]`

| Key | Default | Values and meaning |
|---|---|---|
| `arch` | `native` | `native`, `x86_64`, `arm64`. `native` resolves to the host architecture. |
| `mac_storage` | `auto` | `auto`, `bind`, `volume`. Storage mode on macOS. |
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
| `gdb` | `true` | Expose the QEMU gdbstub. |
| `gdb_port` | `1234` | gdbstub TCP port. |
| `kaslr` | `false` | Enable KASLR at runtime (only if the built kernel supports it). |
| `smep` | `true` | Enable SMEP at runtime. |
| `smap` | `true` | Enable SMAP at runtime. |
| `kpti` | `true` | Enable KPTI at runtime. |
| `panic` | `halt` | `halt` (stay stopped), `reboot`, or another value for a timed reboot. |
| `capture_console` | `true` | Tee the guest serial console to `logs/console.raw`. |
| `ssh_port` | `2222` | Host-side SSH port forwarded into the guest. |
| `share_dir` | `exploit` | Host directory shared into the guest at `/mnt/exploit`. |
| `guest_net` | `true` | Enable guest networking (the SSH transport for `--run` and `--insmod`). |
| `share` | `true` | Enable the 9p live share. |

The runtime mitigation toggles (`kaslr`, `smep`, `smap`, `kpti`) may only turn on behavior the
built kernel actually supports. Asking for a toggle the kernel was not built for is a
configuration error, not a silent no-op.

### `[debugger]`

| Key | Default | Values and meaning |
|---|---|---|
| `ext` | `pwndbg` | `pwndbg`, `gef`. The GDB extension. |
| `break_on_crash` | `true` | Auto-break GDB at a fault to capture a symbolized backtrace. |
| `crash_breakpoints` | `panic`, `die`, `oops_enter` | Fatal-fault symbols the auto-break halts on immediately. |
| `sanitizer_breakpoints` | (empty) | Opt-in KASAN/UBSAN symbols (e.g. `kasan_report`) to halt on, armed only after the guest reaches userspace via a one-shot gate. Empty by default: a KASAN kernel with the text-poke false positive floods `kasan_report`, so prefer a manual `break kasan_report` right before the exploit. KASAN is captured from the console into `crash.md` regardless. |
| `debuginfod` | `auto` | `auto`, `on`, `off`. Fetch debug info by build-id. `auto` is on for `[foreign]` runs and off for self-built kernels (which already carry their symtab). |
| `debuginfod_urls` | elfutils server | Space-separated debuginfod server URLs. Default is the federated `https://debuginfod.elfutils.org`. |

### `[debugging]`

| Key | Default | Values and meaning |
|---|---|---|
| `profiles` | `["exploit-dev"]` | The active debug profiles (see above). |

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
| `exploit` | Optional exploit source or binary, repack-injected at `/exploit`. |
