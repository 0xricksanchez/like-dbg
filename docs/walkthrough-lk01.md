# A guided walkthrough: the LK01 use-after-free

This is a full end-to-end session that ties the whole tool together. You will build a kernel, load
a deliberately vulnerable driver, trigger a use-after-free, let KASAN and crash intelligence catch
it, and then find the same bug by hand in the debugger. It uses the bundled `lk01` driver and its
PoC, so nothing else is needed. It has been run end to end on both x86_64 and arm64.

It assumes you have done the [README quickstart](../README.md#quickstart) (`uv sync` and a running
`tmux -L likedbg` session). Two contexts appear below: the **Debugger (gdb) pane** inside tmux, and
a **host shell** where you run `start_kgdb` subcommands.

## The target

`lk01` (see [modules/lk01/README.md](../modules/lk01/README.md)) is a small slot-based object
manager with four ioctls: allocate an object into a slot, write to it, read from it, and free it.
The bug is in the free path: it releases the object but never clears the slot, so the slot pointer
is left dangling. Write and read guard the slot only by checking that the pointer is non-NULL,
which a freed-but-not-cleared slot still is, so an access after a free is a use-after-free the
check does not stop. The PoC (`expl.c`) drives exactly that: allocate a slot, free it, then write
the slot again.

Nothing faults at the free; the symptom appears later, on the dangling access. That displacement is
the point: you have to work backward from the fault to the free, which is what the rest of this
walkthrough does.

## 1. Build and boot with KASAN

KASAN turns the silent use-after-free into a precise report that crash intelligence records.

Build an `exploit-dev` kernel with KASAN added:

```sh
uv run ./start_kgdb --profile exploit-dev,kasan
```

The first KASAN build is slow (several minutes; it is cached afterward). When it finishes, gdb lands
at `start_kernel`. In the Debugger pane, boot to userspace:

```gdb
continue
```

Wait for the login prompt in the Debuggee pane. By default the debugger does not halt on KASAN
reports, so the kernel's benign boot-time KASAN reports (an x86 text-poke false positive) print to
the console without stopping gdb, and the boot runs straight through. The exploit's use-after-free
is still captured either way; see [Optional: halt gdb at the KASAN report](#optional-halt-gdb-at-the-kasan-report)
if you want to land at the fault in the debugger.

## 2. Load the vulnerable driver

From a host shell, build and load `lk01` into the live guest:

```sh
uv run ./start_kgdb --insmod ./modules/lk01
```

The guest logs `lk01: loaded, /dev/lk01 ready`, and the module's symbols auto-load in gdb at your
next stop.

## 3. Trigger the use-after-free

Put the PoC where the exploit loop expects it, then run it:

```sh
cp modules/lk01/expl.c exploit/
uv run ./start_kgdb --run ./exploit/expl.c
```

`--run` auto-compiles `expl.c` (static musl, guest architecture) and runs it in the guest. The
second write lands on freed memory, KASAN detects it, and `--run` reports the crash:

```text
[likedbg] kernel crashed: kasan (see artifacts/runs/latest/crash.md)
```

The KASAN report on the console (the Debuggee pane) is the whole bug in one place (an x86_64 run
is shown; on arm64 the first line names `lk01_write` directly, but the report is equivalent):

```text
BUG: KASAN: slab-use-after-free in _copy_from_user+0x32/0x80
Write of size 128 at addr ffff8880... by task expl/...
 ... lk01_write+0xe2/0x150 [lk01] ...
Allocated by task ...:
 ... lk01_alloc+0xbe/0x1d0 [lk01]
Freed by task ...:
 ... lk01_free+0x55/0x80 [lk01]
The buggy address belongs to the freed 128-byte region [ffff8880..., ...)
```

The access is in `lk01_write`, the 128-byte object was allocated in `lk01_alloc` and freed in
`lk01_free`, and it is a slab use-after-free. KASAN reports it but does not panic, so the guest
keeps running.

## 4. Read the crash report

Crash intelligence captured the KASAN report into the run directory:

```sh
uv run ./start_kgdb --analyze-crash        # regenerate from the latest run
```

`artifacts/runs/latest/crash.md` summarizes the use-after-free as the primary event, with the
faulting function and the allocate and free sites, ready to drop into notes or a writeup.

## 5. Find the same bug by hand

The report told you what; now see why in the debugger. The module symbols are already loaded (from
`--insmod`), so break on the free path. In the Debugger pane:

```gdb
break lk01_free
```

This resolves to `lk01.c:71`. Run the PoC again from a host shell
(`uv run ./start_kgdb --run ./exploit/expl.c`). Because gdb stops the guest at the breakpoint, the
`--run` invocation waits; inspect, then `continue`.

When gdb stops in `lk01_free`, watch the slot pointer survive the free:

```gdb
print lk01_slots[0]      # {ptr = 0xffff8880..., len = 128}
next                     # step over the kfree
print lk01_slots[0]      # same ptr: freed, but the slot still points at it (dangling)
```

To see the other half, break on `lk01_write` (`lk01.c:83`) as well. Note it fires on the *valid*
write before the free too, so continue to the call that happens after `lk01_free`: there the guard
`if (!o->ptr)` passes because the pointer is non-NULL (though dangling), and `copy_from_user` writes
into the freed object. That is the use-after-free the non-NULL check fails to prevent.

## Optional: halt gdb at the KASAN report

By default the debugger captures KASAN reports from the console (into `crash.md`) but does not stop
gdb at them, because a KASAN kernel like this one emits a benign text-poke KASAN false positive that
floods `kasan_report` throughout boot and init. To land in the debugger *at* the exploit's fault,
arm `kasan_report` by hand in the Debugger pane right before you run the exploit, so you skip the
boot and init flood:

```gdb
break kasan_report
```

Then run the PoC from a host shell; gdb halts at `kasan_report` with the use-after-free's live
registers and backtrace. You can also set `[debugger] sanitizer_breakpoints = ["kasan_report"]` in
config to arm it automatically once userspace is reached, but on this kernel it still trips on the
boot and init text-poke reports first, so the manual "arm it right before the exploit" approach is
cleaner here. On a KASAN kernel without the text-poke false positive, the config option works
cleanly.

## The loop's commands and mechanisms

You used several of these above. Here is the whole set and how each one works, so you can drive the
loop by hand.

### The shared exploit directory (9p)

The host `exploit/` directory is mounted into the guest at `/mnt/exploit` over 9p, live and
read-write in both directions: edit or build a file on the host and it appears in the guest at once,
and anything the exploit writes to `/mnt/exploit` shows up back in `exploit/` on the host. Because
that output lives on the host, it survives a kernel panic. This is why `--run` can deliver in place
with no copy, and why you can drop a prebuilt binary in `exploit/` and run it from the guest as
`/mnt/exploit/<name>`. The host directory (`share_dir`, default `exploit`) and whether the share is
enabled (`share`) are configurable (see [configuration.md](configuration.md)).

### Automatic exploit building and delivery: `--run`

`--run <path>` finds the live session, delivers the exploit, runs it in the guest over SSH,
captures its stdout, stderr, and any files into the run directory, then chains crash analysis. A
single flag-less `.c` is auto-compiled to a static-musl binary for the guest architecture
(`zig cc -target <arch>-linux-musl -static`); anything else (a prebuilt binary, C++, multiple files,
custom flags, assembly, or a glibc-semantics exploit) is delivered unchanged. Pass argv with
`--args "1 2 3"`. The full compile boundary and the prebuilt-binary escape hatch are in
[exploit/README.md](../exploit/README.md).

### Delivery over the serial console: `--upload`

`--upload <path>` streams the exploit into the running guest as base64 over the serial console
(same auto-compile rule), for when the SSH and 9p transport is not available, such as a foreign CTF
kernel. See [ctf-foreign-kernel.md](ctf-foreign-kernel.md).

### Building and loading a module: `--insmod`, `--rmmod`, `--force-unload`

`--insmod <path>` builds the module out-of-tree against the running kernel (only if stale) and loads
it live; its symbols auto-load in gdb at your next stop. `--rmmod <name>` unloads it, and
`--force-unload` forces a busy device out. See [modules/README.md](../modules/README.md).

### Talking to the guest directly: SSH and scp

`--run` and `--insmod` reach the guest over SSH automatically, but you can too. The guest is
reachable on the host at `127.0.0.1:2222` (the `ssh_port`). Log in as `root` with the ed25519 key
the rootfs baked (stored mode `0600` under `artifacts/rootfs/`, and recorded as `ssh_key` in the
rootfs manifest):

```sh
ssh -i artifacts/rootfs/<rootfs-label>.img.id_ed25519 -p 2222 root@127.0.0.1
scp -i artifacts/rootfs/<rootfs-label>.img.id_ed25519 -P 2222 ./thing root@127.0.0.1:/mnt/exploit/
```

Run `ls artifacts/rootfs/*.id_ed25519` to find the key file. There is also an unprivileged `user`
account (password `user`) for working from a non-root perspective.

### Inspecting a crash offline: `--analyze-crash`

`--analyze-crash [run-id]` rebuilds `crash.json` and `crash.md` for a run from its captured console
and gdb-live state, entirely on the host with no running guest. Useful after the fact or when tuning
the report.

## Where to go from here

- **Turn it into a real exploit.** After the free, spray allocations of the same size (another
  `lk01` slot, or a kernel object of the right size) to reclaim the freed chunk, then the dangling
  write and read become a controlled read/write over whatever now occupies that memory. That is the
  standard use-after-free-to-arbitrary-read/write path.
- **Change the difficulty with mitigations.** Rebuild with `--profile hardened`, or toggle
  `kaslr`, `smep`, `smap`, and `kpti` at runtime (see [configuration.md](configuration.md)), and
  watch how each one changes the work.
- **Iterate.** Edit `exploit/expl.c` and `--run` it again; module symbols and the crash loop stay
  wired up, so each attempt lands you back at the fault with full context.
