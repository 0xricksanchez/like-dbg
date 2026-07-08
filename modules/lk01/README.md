# lk01: a deliberately vulnerable training driver

`lk01` registers `/dev/lk01` (a misc char device) as a small slot-based object manager with four
ioctls: `LK01_ALLOC` (kmalloc an object into a slot), `LK01_WRITE` and `LK01_READ` (copy to and
from it), and `LK01_FREE` (release it).

**The bug (intentional):** `LK01_FREE` frees the object but never clears the slot, leaving the
slot's pointer dangling. `LK01_WRITE` and `LK01_READ` guard the slot only by checking that the
pointer is non-NULL, which a freed-but-not-cleared slot still is, so a write or read after a free
is a use-after-free the check does not catch. Nothing faults at the free; the symptom shows up
later on the dangling access. See the header comment in `lk01.c` for the full note.

This is a small, original, LK01/Pawnyable-style training driver, clearly labeled as intentionally
vulnerable and meant only for a local debugger sandbox. Do not load it on anything but a disposable
debug kernel.

`expl.c` is a use-after-free demonstrator, not a working exploit: it allocates a slot, frees it,
then writes to the slot again. On a KASAN kernel the second write raises a use-after-free report;
on a plain kernel it corrupts freed memory silently. It is a starting point for a real exploit
(reclaim the freed slab with a controlled object, turning the dangling slot into an arbitrary
read/write), not an LPE.

## Using it

The `lk01.c` driver and the `expl.c` PoC are both flag-less single sources, so LIKE-DBG builds
them for you: `--insmod` builds the module out-of-tree against the running kernel, and `--run`
auto-compiles the PoC static-musl to the guest architecture.

```bash
uv run ./start_kgdb --insmod ./modules/lk01     # build + load the driver into the live guest
cp modules/lk01/expl.c exploit/                  # the PoC lives with the driver; copy it to exploit/
uv run ./start_kgdb --run ./exploit/expl.c       # auto-compile + run
```

To have the use-after-free caught deterministically (a KASAN report captured in a crash report),
build with KASAN: `uv run ./start_kgdb --profile exploit-dev,kasan`. Set
`[debugger] break_on_crash = false` in `configs/local.toml` first: a KASAN kernel prints benign
reports during early boot that the crash auto-break would otherwise trap. See the
[LK01 walkthrough](../../docs/walkthrough-lk01.md) for the full session.

For the complete guided session (build, boot, arm gdb, load the driver, trigger the
use-after-free, read the crash report, and debug it by hand), see the
[LK01 walkthrough](../../docs/walkthrough-lk01.md).
