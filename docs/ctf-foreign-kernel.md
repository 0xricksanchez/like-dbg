# Debugging a CTF or foreign kernel

A foreign kernel is one LIKE-DBG did not build: a ready-made `bzImage` or `Image` (plus,
optionally, a `vmlinux` and an `initramfs`) that a CTF challenge or a triage case hands you.
Instead of downloading and compiling a kernel, LIKE-DBG adopts the provided artifacts and boots
them verbatim under GDB with an interactive serial console.

This path is deliberately narrow. A foreign kernel has no `/ksrc` build tree and no LIKE-DBG root
filesystem, so the SSH and 9p transport used for a self-built kernel does not apply: `--run` and
`--insmod` are unavailable here, and exploit delivery goes over the initramfs or the serial
console (see [Deliver an exploit](#deliver-an-exploit)). If you are building the kernel yourself,
use [build-your-own-kernel.md](build-your-own-kernel.md) instead.

## What you get from a challenge

Challenges ship different subsets of files. What you have decides what you can do:

| You have | What it gives you |
|---|---|
| `bzImage` / `Image` (required) | Boots the kernel with an interactive serial console. Its presence selects the foreign path. |
| `vmlinux` (optional) | Function symbols in GDB. Without it, an x86 kernel can auto-extract a stripped `vmlinux` (enough for arch detection and kallsyms, but no function symbols); an arm64 `Image` must supply `vmlinux` explicitly. |
| `initramfs` (optional) | The challenge root filesystem, and the target for repack-based exploit delivery. |
| `cmdline` | The challenge's boot command line, used verbatim. |

## Describe it in a scenario config

A foreign kernel is declared in a `[foreign]` block in a scenario config. Copy the shipped
template and edit it:

```sh
cp configs/scenarios/example-foreign.toml.example configs/scenarios/lk01.toml
```

```toml
[foreign]
image = "ctf/lk01/bzImage"                     # boot image; its presence selects the foreign path
vmlinux = "ctf/lk01/vmlinux"                   # optional; provides GDB symbols
initramfs = "ctf/lk01/initramfs.cpio.gz"       # optional; the challenge rootfs
cmdline = "console=ttyS0 kaslr quiet panic=-1" # used verbatim; only console= and the gdbstub are added
# arch = "x86_64"                              # optional; else auto-detected from the vmlinux ELF
# qemu_extra = ["-cpu", "qemu64,+smep,+smap"]  # mirror the challenge's extra QEMU flags
# exploit = "ctf/lk01/exploit.c"               # optional; repack-inject at /exploit (see below)
```

Paths may be absolute or workspace-relative, since challenge artifacts often live outside the
repo (for example under `~/ctf/<name>/`).

## Boot it

```sh
uv run ./start_kgdb -c lk01
```

LIKE-DBG adopts the kernel without a Manifest: it skips download, build, and post-build `.config`
verification (there is no `.config`), detects the architecture from the `vmlinux` ELF, and boots
the image under GDB. The provided `cmdline` is passed through verbatim; only the console setting
and the gdbstub option are appended.

## Symbols

With an explicit `vmlinux`, GDB gets whatever symbols it carries (full DWARF if present). Without
one:

- An **x86** `bzImage` gets **function symbols recovered automatically** from its kallsyms table
  (via `vmlinux-to-elf` inside the `like_musl` container), so `kmod`, kernel-symbol breakpoints,
  and backtraces work with no setup. The recovery is trusted only if it passes a sanity gate (a
  real symbol table with `_stext` in the kernel address range); otherwise LIKE-DBG falls back to a
  stripped, decompress-only carve (architecture detection only, no function symbols) and logs a
  warning. Source-level (line/type) debugging still needs a real `vmlinux`. The recovered `vmlinux`
  is cached per challenge, so only the first boot pays for it.
- An **arm64** `Image` is not yet auto-recovered; provide `vmlinux` explicitly (see Limitations).

If architecture detection fails or is wrong (an unusual image, or no usable `vmlinux`), set
`[foreign] arch` to `x86_64` or `arm64`.

`[debugger] debuginfod` defaults to `auto`, which is on for a `[foreign]` run. GDB queries a
debuginfod server by the kernel's build-id before loading `vmlinux`, so a stock distro or n-day
kernel (whose build-id is commonly indexed by a public or vendor debuginfod server) can regain
full function symbols even from the stripped, kallsyms-only auto-extracted x86 `vmlinux` above. A
bespoke CTF kernel with a build-id no server has ever indexed simply gets no match; GDB falls back
to whatever symbols it already had, with no other effect. Set `[debugger] debuginfod = "off"` to
disable the lookup outright, or `debuginfod_urls` to point at a private mirror; see
[configuration.md](configuration.md#debugger) for both knobs.

## Deliver an exploit

There is no SSH or 9p share, so the exploit reaches the guest one of two ways. In both, you run
it **manually from the guest console** (for example `/exploit`); nothing is auto-run.

**Repack (baked into the initramfs).** Set `[foreign] exploit` to a source or binary path. At
boot, LIKE-DBG unpacks the provided `initramfs`, places the exploit at `/exploit`, and repacks.
A flag-less `.c` is auto-compiled static-musl to the target architecture; anything else is
injected as-is (cross-compile it yourself). Changing the exploit means another repack and reboot.
The unpack, compile, and repack happen inside the standalone `like_musl` container, so no host
`cpio`, `musl`, or root is required.

**Console-upload (into the live guest).** Send the exploit to the running guest over the serial
console, with no reboot, when the guest supports it:

```sh
uv run ./start_kgdb --upload ./exploit/poc.c   # a flag-less .c is compiled, then base64-streamed
uv run ./start_kgdb --upload ./exploit/poc      # a prebuilt binary is streamed as-is
```

The auto-compile boundary and the prebuilt-binary escape hatch are the same as for a self-built
kernel; see [exploit/README.md](../exploit/README.md).

## Mirror the challenge's QEMU setup

Match the challenge's runtime so your exploit behaves as it does on the remote:

- `cmdline` is used verbatim, so copy the challenge's boot arguments exactly (KASLR, `panic=`,
  and the rest).
- `qemu_extra` adds QEMU flags, for example a specific CPU baseline with `-cpu
  qemu64,+smep,+smap`, so the guest's mitigations and instruction set match the target.

## Worked example: Pawnyable LK01

Pawnyable's LK01 ("Holstein v1", by ptr-yudai) is a good first foreign target: a stack buffer
overflow in a char driver with every mitigation off. LIKE-DBG ships a ready-made scenario
([`configs/scenarios/pawnyable-lk01.toml`](../configs/scenarios/pawnyable-lk01.toml)); you supply
the challenge artifacts. Get `bzImage` and `rootfs.cpio` from the challenge's `LK01/qemu/`
directory and drop them where the scenario expects them (under gitignored `ctf/`, so they are
never committed):

```sh
mkdir -p ctf/pawnyable-lk01
cp <pawnyable>/learn/linux-kernel/LK01/qemu/{bzImage,rootfs.cpio} ctf/pawnyable-lk01/
uv run ./start_kgdb -c pawnyable-lk01
```

The scenario reproduces the challenge's `run.sh` exactly: a Linux 5.10.7 `bzImage`, `-m 64M`, a
bare `-cpu qemu64` (no SMEP/SMAP), and the verbatim `nopti nokaslr` command line, so KASLR, KPTI,
SMEP, and SMAP are all off. The challenge's own initramfs loads the `vuln.ko` driver at boot,
creates `/dev/holstein`, and drops you to an unprivileged (uid 1337) shell; the goal is local
privilege escalation to root.

The bug is a classic stack overflow: the driver's `read`/`write` handlers copy a user-controlled
`count` into a fixed `char kbuf[0x400]` on the stack. GDB attaches at the gdbstub with full access
to kernel memory. To debug the driver by name, use pwndbg's `kmod` to find where the module loaded.
For source-level symbols, build the driver from the challenge's `vuln.c` (in its `src/`) with `-g`
and point `add-symbol-file` at the resulting `vuln.ko` in the GDB pane:

```gdb
add-symbol-file <your-build>/vuln.ko <.text load address>
break module_write
```

No `vmlinux` ships with the challenge, but LIKE-DBG recovers kernel function symbols from the
`bzImage`'s kallsyms automatically, so `kmod` and kernel breakpoints work out of the box. For
source-level kernel debugging, build a matching 5.10.7 `vmlinux` and point `[foreign] vmlinux` at
it. Writing the exploit is left to you, as the challenge intends.

## Limitations

- **Serial-only transport.** No SSH, no 9p share, and therefore no `--run` and no `--insmod`.
  Exploit delivery is repack or console-upload, and the exploit is run by hand from the console.
- **x86 symbols are auto-recovered; arm64 is not yet.** A bare x86 `bzImage` gets function symbols
  recovered from kallsyms automatically; an arm64 `Image` still needs an explicit `vmlinux` (arm64
  kallsyms recovery is a planned follow-up). Source-level (line/type) debugging on any arch still
  needs a real `vmlinux`.
- **Repack needs the `like_musl` container,** which is built on first use.
- **Crash capture still works, symbolization does not always.** The serial console is captured to
  the run's `logs/console.raw`, so `--analyze-crash` produces a report from console output. A
  symbolized GDB backtrace at the fault requires `vmlinux` symbols.
