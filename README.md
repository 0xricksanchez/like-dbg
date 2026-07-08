# LIKE-DBG

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status: flake8](https://github.com/PyCQA/flake8/workflows/main/badge.svg)](https://github.com/0xricksanchez/like-dbg/actions?query=workflow%3Aflake8)
[![Build Status: shellcheck](https://github.com/koalaman/shellcheck/actions/workflows/build.yml/badge.svg)](https://github.com/0xricksanchez/like-dbg/actions?query=workflow%3Ashellcheck)
[![Build Status: hadolint](https://img.shields.io/badge/hadolint-passing-brightgreen)](https://github.com/0xricksanchez/like-dbg/actions?query=workflow%3Ahadolint)
[![codecov](https://codecov.io/gh/0xricksanchez/like-dbg/branch/main/graph/badge.svg?token=SXF37MH4X6)](https://codecov.io/gh/0xricksanchez/like-dbg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://tldrlegal.com/license/mit-license)
[![GitHub Release](https://img.shields.io/github/release/0xricksanchez/like-dbg.svg)](https://github.com/0xricksanchez/like-dbg/releases/)

LIKE-DBG (*LI*nux-*KE*rnel-*D*e*B*u*G*ger) aims at automating the boring steps when trying to set up a Linux kernel debugging environment.
I set out to dive into kernel exploitation research and found existing solutions not usable enough.
Hence, this is an attempt at making all necessary pre-steps before one can even think about diving into research as painless and fun as possible.
All steps from building a kernel, running it inside an emulated environment, and attaching a debugger are transparently done inside docker containers to keep system requirements minimal.
Currently, there's a dedicated docker container for every of the following steps:

- Building the kernel
- Creating a root file system to use with the kernel
- Launching the kernel + file system as the _debuggee_
- Attaching to the kernel as a _debugger_

## Caveats

As this project is in its early stages, I expect things to change rapidly, while also introducing breaking changes along the way.
Major points to improve on are:

- Getting towards true multi-architecture support beyond `x86_64` and `arm64`
- Extend kernel builder to not only succeed in building recent™ kernels
- Add android kernel support
- Add (integration) tests
- Elevate the debugging experience even more

## Features

On the upside, despite its early stages, a couple of useful features are already present:

- General:
  - Minimal host system requirements due to dockerization of every step
  - An easy to grasp `configs/user.ini` config that allows highly customizable sessions
    - Or provide different configurations for different debugging setups via the command-line!
  - CTF runner that's specifically designed to handle Linux kernel exploitation challenges
    - `ctf/misc` that houses some nifty scripts to aid in CTFs
  - Code quality measures:
    - [black](https://github.com/psf/black) formatter for python code
    - [flake8](https://github.com/PyCQA/flake8) linter for all python code
    - [shellcheck](https://github.com/koalaman/shellcheck) linter for shell scripts
    - [hadolint](https://github.com/hadolint/hadolint) linter for the Dockerfiles
  - Operating system agnostic, meaning it should run just fine on:
    - Debian/Ubuntu
    - Arch Linux/Manjaro
    - Fedora
- Kernel builder:
  - Multi-arch: `x86_64`, `arm64`
  - Choose between `gcc` and `clang` to build the kernel
  - Configuration modes:
    - generic-mode,
    - syzkaller-mode,
    - custom-mode, or
    - provide a usable kernel config
  - Fine-granular version control to build from:
    - Commit hash
    - Release tag (e.g.: 5.10-rc)
    - Major-Minor-Patch (e.g.: 5.10.77)
  - Ability to automatically apply patch files
  - Basic ability to add custom kernel modules
- Root file system builder:
  - Powered by [debootstrap](https://wiki.debian.org/Debootstrap)
  - Automatic generation of file system that matches the kernels architecture
  - Ability to customize:
    - wanted packages in the file system
    - the Debian release version to base everything on
- Debuggee:
  - Powered by [QEMU](https://github.com/qemu/qemu)
  - Customization of QEMU runtime options from within the `configs/*.ini` files.
- Debugger:
  - Powered by [GDB (multiarch)](https://sourceware.org/gdb/) with either
    - [GEF](https://github.com/hugsy/gef) and [GEF-extras](https://github.com/hugsy/gef-extras), or
    - [pwndbg](https://github.com/pwndbg/pwndbg)
  - Allow users to specify GDB script in `io/scripts/gdb_script` to allow a scenario-tailored debugging experience

## Requirements

To get started, you have to ensure to have the following requirements set up in your system:

- `docker`
- `tmux`
- `python>=3.12`
- `uv` # <https://docs.astral.sh/uv/>

It is recommended to not run this as the `root` user, e.g. for testing purposes on a VPS.
It may work fine but in general I highly encourage creating a dedicated non-root user to put in the `docker` and `sudo` group!

### Optional

This section covers tools that are _not_ required to run LIKE-DBG but are nice to have and assist heavily when debugging or writing an exploit.

- [musl-gcc](https://www.musl-libc.org/how.html)
- [ctags](https://github.com/universal-ctags/ctags)
- [ropr](https://github.com/Ben-Lichtman/ropr)

## Setup

Inside `like-dbg` run `uv sync`

## Configuration

LIKE-DBG uses a TOML configuration stack. The files, in precedence order (highest last):

| File | Description |
|---|---|
| `configs/default.toml` | Tracked project defaults. Edit for repo-wide changes. |
| `configs/local.toml` | Gitignored personal overrides (create from `configs/local.example.toml`). |
| `configs/scenarios/<name>.toml` | Named scenario configs, loaded with `-c <name>` or `-c <path>`. |

CLI flags always win over all config files.

**Everyday mental model:** three layers — project defaults, local/scenario, CLI. The full
six-layer provenance model is internal and is recorded in `settings.effective.json` for
artifact inspection.

### Debug profiles

Debug profiles control what kernel you build and the debugging experience you get:

```sh
# Default: exploit-dev (no KASLR, debug info, kallsyms, frame pointers)
uv run ./start_kgdb

# Explicit profile
uv run ./start_kgdb --profile kasan

# Multiple profiles (comma-separated; overrides debugging.profiles in TOML)
uv run ./start_kgdb --profile hardened,lockdep

# Inspect resolved config without building or booting
uv run ./start_kgdb --explain-config
uv run ./start_kgdb --explain-config json
```

Available profiles:

| Profile | Kind | Purpose |
|---|---|---|
| `exploit-dev` | base | No KASLR, debug symbols, kallsyms — the daily-driver default |
| `hardened` | base | Mitigations compiled in; toggle KASLR/SMEP/SMAP/KPTI at runtime |
| `crash-debug` | add-on | Verbose BUG/oops/sysrq for readable stack traces |
| `kasan` | add-on | KASAN memory-bug detection (implies `crash-debug`) |
| `ubsan` | add-on | UBSAN undefined-behavior detection (implies `crash-debug`) |
| `lockdep` | add-on | Lock-ordering and concurrency diagnostics |
| `kcov-lite` | add-on | KCOV + debugfs for later coverage-guided work |

`exploit-dev` and `hardened` are mutually exclusive (conflicting KASLR build-time decisions).
Custom profiles can be added by placing a TOML file under `configs/profiles/`.

**GDB extension:** `pwndbg` is the default (`[debugger] ext = "pwndbg"` in `default.toml`).
To use GEF instead, add `[debugger] ext = "gef"` to `configs/local.toml`.

### Inspecting config

`--explain-config` resolves the full TOML stack and profiles without touching Docker, tmux, or
run directories. Add `json` for machine-readable output:

```sh
uv run ./start_kgdb --explain-config
uv run ./start_kgdb --profile kasan --explain-config json
```

## Usage

**Note:** On first time usage run `uv sync`.

Once you're set with writing/adapting a configuration, the usage depends on your scenario.
The easiest way to get started, which is based on the `configs/user.ini` configuration is the following:

```sh
tmux -L likedbg -f .tmux.conf new -s LIKE-DBG
```

Then inside that tmux session:

```sh
# This checks out a kernel, builds it, creates a root file system and starts the debugger and debuggee eventually
uv run ./start_kgdb
```

The `-L likedbg` socket name makes tmux start an isolated project server, so
the checked-in `.tmux.conf` is definitely loaded. Because this is not the
default tmux server, use the same socket name when listing or reattaching:

```sh
# Detach with C-b d
tmux -L likedbg ls
tmux -L likedbg attach -t LIKE-DBG
```

If you intentionally run LIKE-DBG inside an existing tmux server, load the
project config into that server first:

```sh
tmux source-file "$PWD/.tmux.conf"
```

The project tmux config binds `C-b B` to restart the Debuggee pane in place. If
you use a custom tmux config, keep an equivalent fallback binding or run:

```sh
uv run ./start_kgdb --restart-debuggee
```

Restarting the Debuggee relaunches QEMU and keeps the Debugger pane open, but
GDB loses the old remote target. Run `likedbg-reconnect` in GDB/pwndbg after
the restart; it reconnects to the new QEMU gdbstub and resumes to `start_kernel`.
Do not use `target remote :1234` or `target remote localhost:1234` from inside
the Debugger container: `localhost` is the container, not the host QEMU process.
If you need a raw manual attach, use `target remote host.docker.internal:1234`.

There exist 2 users for the automatically created filesystems:

- `root` with no password
- `user`:`user`

This is intended so you can develop and exploit from either perspective easily.

### Extended Usage

```sh
# Load a named scenario config (configs/scenarios/lk01.toml) or an explicit path
uv run ./start_kgdb -c lk01
uv run ./start_kgdb -c /path/to/my.toml

# Rebuild all LIKE-DBG container images
uv run ./start_kgdb --build-images

# List cached Kernel Builds and rootfs images
uv run ./start_kgdb --list

# Remove one cached artifact, or clear the cache
uv run ./start_kgdb --clean <label>
uv run ./start_kgdb --clean-all

# Reuse an existing Kernel Build. If the active rootfs is missing, --use builds it;
# --rootfs pins a cached rootfs label instead.
uv run ./start_kgdb --use <build-label>
uv run ./start_kgdb --use <build-label> --rootfs <rootfs-label>

# Adopt a manually created legacy rootfs image into the keyed cache
uv run ./start_kgdb --adopt-rootfs
uv run ./start_kgdb --adopt-rootfs <path-to-rootfs-img>

# Force the current Kernel Build to rebuild
uv run ./start_kgdb --force-rebuild

# Restart the Debuggee pane from stored tmux session state
uv run ./start_kgdb --restart-debuggee
```

### Exploit-dev loop

```sh
# Run/upload an exploit against the live session. A single flag-less `.c` is
# auto-compiled (static musl, target arch) before delivery; any other file is
# delivered as-is — the escape hatch for C++, multi-file, custom flags, assembly,
# or a glibc-semantics exploit (pass a prebuilt static binary for those).
uv run ./start_kgdb --run ./exploit/poc.c        # compiled, then run
uv run ./start_kgdb --run ./exploit/poc          # prebuilt binary, delivered as-is
uv run ./start_kgdb --upload ./exploit/poc.c     # compiled, delivered over the serial console

# Build (if stale) + load an out-of-tree module; symbols auto-load in gdb at
# your next stop (or `source /exploit/modules.gdb` in the gdb pane to apply now).
uv run ./start_kgdb --insmod ./modules/lk01
uv run ./start_kgdb --rmmod lk01
```

Kernel runs default to `pwndbg` for in-gdb introspection (KASLR base, slab, `current`, task/module
walking, symbol lookup — `kbase`/`slab`/`kcurrent`/`ktask`/`klookup`/`kmod`/`kallsyms`); like-dbg's job
is compiling to the target arch, delivering host↔guest, and feeding gdb the right artifact/symbols, not
reimplementing that introspection. See `exploit/README.md` for the compile boundary + escape hatch,
`modules/README.md` for the module-symbol auto-load lifecycle, and `docs/adr/0011-exploit-dev-seams.md`
for the design rationale.

### Run artifacts

Every interactive Debugging session creates a timestamped run directory:

```text
artifacts/runs/<YYYYMMDDTHHMMSSZ>-<build-label>/
  run.json                  # schema-versioned index + status machine
  settings.requested.json   # TOML + CLI config before profile resolution
  settings.effective.json   # actual settings used (with per-key provenance)
  host.json                 # host profile (OS, arch, accel, storage mode)
  profiles.json             # full profile resolution graph + warnings
  commands/                 # qemu.sh, gdb.sh, *.argv.json
  logs/
    likedbg.log             # LIKE-DBG process log for this run
    debuggee-pane.log       # QEMU pane transcript
    debugger-pane.log       # GDB/pwndbg pane transcript
  kernel/
    config                  # copy of the built .config
    System.map.pointer      # path pointer
    vmlinux.pointer
    image.pointer
  notes.md
```

`artifacts/runs/latest` symlinks to the most recent run (even failed ones).
`artifacts/logs/latest.log` symlinks to that run's `logs/likedbg.log`.

**Run status set:** `created` → `profile-verification-failed` | `launching` → `launched` |
`launch-failed`. Profile verification must pass before the Debuggee is launched.

**Pane transcripts** are operator-pane logs captured via `tmux pipe-pane`. They are not
byte-perfect serial capture: a small amount of output may be missed between pane creation and
`pipe-pane` activation, and there is a gap in each log at every `C-b B` Debuggee restart (the pane
is re-piped in append mode, but the instant of restart is not captured). If you need byte-perfect
serial logs, use QEMU `-serial` options directly; this is planned for a later slice.

### Examples

The `examples` subdirectory houses samples on how `LIKE_DBG` may aid you in specific kernel debugging tasks.
Each example contains a dedicated `README.md` as well that contains the necessary information to reproduce the examples.

## Showcase

![img/example.png](img/example.png)

## Hacking

The python code should be quite readable, so feel free to extend the project with your own ideas. All PRs are very much welcome :)!
Otherwise, feel free to create a feature-request issue or head over to the [discussions page](https://github.com/0xricksanchez/like-dbg/discussions) to brainstorm some cool new features!

PS: If you want to provide a logo, feel free to do so.
