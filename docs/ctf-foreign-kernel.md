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

With a `vmlinux`, GDB gets full function symbols. Without one:

- An **x86** kernel auto-extracts a `vmlinux` carved from the boot image. It is fully stripped
  (kallsyms only, no ELF symbol table), which is enough for architecture detection but gives GDB
  no function symbols.
- An **arm64** `Image` cannot be auto-extracted; provide `vmlinux` explicitly.

If architecture detection fails or is wrong (an unusual image, or no usable `vmlinux`), set
`[foreign] arch` to `x86_64` or `arm64`.

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

## Limitations

- **Serial-only transport.** No SSH, no 9p share, and therefore no `--run` and no `--insmod`.
  Exploit delivery is repack or console-upload, and the exploit is run by hand from the console.
- **Symbols depend on `vmlinux`.** A bare `bzImage` without `vmlinux` gives GDB no function
  symbols; fall back to pwndbg's kallsyms-based introspection. An arm64 `Image` always needs a
  provided `vmlinux`.
- **Repack needs the `like_musl` container,** which is built on first use.
- **Crash capture still works, symbolization does not always.** The serial console is captured to
  the run's `logs/console.raw`, so `--analyze-crash` produces a report from console output. A
  symbolized GDB backtrace at the fault requires `vmlinux` symbols.
