# lk01 — a deliberately vulnerable training driver

`lk01` registers `/dev/lk01` (a misc char device) and exposes one ioctl, `LK01_COPY`. The handler
reads a userspace `struct lk01_arg { size_t len; void *ptr; }` and then runs an **unchecked**
`copy_from_user(kbuf, arg.ptr, arg.len)` into a fixed `char kbuf[64]` on the kernel stack — any
`len > 64` overflows it. See the header comment in `lk01.c` for the full bug note.

This is the standard LK01/Pawnyable-style practice pattern: small, original, clearly labeled as
intentionally vulnerable, meant only for a local debugger sandbox. Do not load it on anything but a
disposable debug kernel.

`expl.c` is a crash-triggering PoC, not a working exploit: it opens `/dev/lk01`, builds a
`lk01_arg` with `len = 4096` and a heap buffer, and fires `LK01_COPY` — the overflow should panic
the guest kernel. It is meant as the starting point for a real exploit (e.g. driving the overflow
into a controlled return-address clobber), not an LPE.

## The loop

1. Point the build at this module (either in config or ad hoc):
   ```toml
   [build]
   custom_modules = ["modules/lk01"]
   ```
   or pass it directly to `--insmod` without touching config (see step 3).
2. Boot a session (`start_kgdb`) — if `custom_modules` is configured, the module-build stage builds
   `lk01.ko` out-of-tree against the session's kernel and stages it into the Guest share.
3. Load it live, once the session is booted and continued past `start_kernel`:
   ```bash
   uv run ./start_kgdb --insmod ./modules/lk01
   ```
   (`--insmod` builds-if-stale even if `custom_modules` wasn't set.) Use `--rmmod lk01` to unload,
   `--force-unload` to force a busy device out.
4. Build the PoC for the guest's architecture (see the cross-compile one-liner below) and drop it
   in `exploit/`.
5. Run it against the live session:
   ```bash
   uv run ./start_kgdb --run ./exploit/lk01_expl
   ```
   Expect a kernel panic; `start_kgdb --analyze-crash` (or the automatic crash report) picks it up.

## Cross-compiling the PoC

`expl.c` is plain userspace C (no kernel headers beyond the UAPI-safe `<linux/ioctl.h>`), so build
it statically for the guest arch using the same kbuilder image the kernel build uses:

```bash
# arm64 guest (from the repo root); adjust --target for x86_64:
docker run --rm -v "$PWD/modules/lk01:/m:ro" -v "$PWD/exploit:/o:rw" like_kbuilder_arm64:latest \
  clang --target=aarch64-linux-gnu -static -o /o/lk01_expl /m/expl.c
```

The kbuilder image is clang-universal (the `_arm64` in its name is a legacy misnomer — it
cross-compiles any arch); for an x86_64 guest, keep the same image and swap only the
`--target=x86_64-linux-gnu`.
