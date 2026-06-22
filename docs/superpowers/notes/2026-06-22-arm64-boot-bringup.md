# arm64 boot/debug bring-up — Plan 3 Task 7 (start_kernel PoC) (2026-06-22)

**Result: SUCCESS.** The built arm64 6.6.30 kernel booted under **native HVF QEMU on the Mac**
and a **containerized gdb** (in the colima VM) attached over `host.docker.internal:1234` and
hit a **hardware breakpoint at `start_kernel`** with full source-level context. This is the
M1 mid-point de-risk: HVF accel + container→host gdbstub networking + artifact export are all
validated on the M5.

## The hit

```
Thread 1 hit Breakpoint 1, start_kernel () at init/main.c:882
882     set_task_stack_end_magic(&init_task);
#0  start_kernel () at init/main.c:882
#1  0xffff800081ad7968 [PAC] in __primary_switched () at arch/arm64/kernel/head.S:523
pc  0xffff800081ad03d4 <start_kernel+20>   sp  0xffff800081ce3e80
```

## Working invocations

Export `Image` to host (vmlinux stays in the volume):
```
docker run --rm -v likedbg_ksrc:/ksrc:ro -v $PWD/artifacts/linux-6.6.30:/out like_dbg_base \
  sh -c 'cp /ksrc/linux-6.6.30/arch/arm64/boot/Image /out/Image'
```
Native QEMU (Mac host), paused at reset, gdbstub on `:1234`:
```
qemu-system-aarch64 -M virt -cpu host -accel hvf -m 2048 -smp 2 \
  -kernel artifacts/linux-6.6.30/Image -append "console=ttyAMA0 nokaslr" -nographic -S -s
```
Containerized gdb attach (single connection — see findings):
```
docker run --rm --add-host=host.docker.internal:host-gateway -v likedbg_ksrc:/ksrc:ro <dbg-image> \
  gdb-multiarch -q -iex "set auto-load safe-path /" /ksrc/linux-6.6.30/vmlinux \
    -ex "set architecture aarch64" \
    -ex "target remote host.docker.internal:1234" \
    -ex "hbreak start_kernel" -ex "continue"
```

## Bring-up findings (folded into the code)

1. **`hbreak`, not `break`, for early-boot breakpoints.** A software breakpoint can't be written
   to the kernel's high-half VA (`0xffff8000...`) before the MMU is enabled at reset
   (`Cannot access memory at 0x...`). `build_gdb_args` now emits `hbreak` for the breakpoint.
2. **`set auto-load safe-path /` must be `-iex`** (before the symbol file loads), else the
   kernel's `vmlinux-gdb.py`/`lx-` helpers are declined. `build_gdb_args` now uses `-iex`.
3. **`--add-host=host.docker.internal:host-gateway`** on the gdb container's `docker run` — with
   it, the colima container reaches the Mac host's gdbstub (confirmed `REACHABLE`). This is a
   wiring detail for the debugger run command (Task 8 / Plan-3 assembly).
4. **Single attach — don't detach/reconnect.** gdb *detach resumes* the QEMU vcpu, so the kernel
   boots past `start_kernel`. The session must keep gdb attached for the duration.
5. A minimal `gdb-multiarch`-only image suffices to prove the plumbing; gef/pwndbg (the richer
   UX) come with the real debugger image (Task 8).

## Open for Task 8 (boot-to-shell = M1 exit gate)

- Build the rootfs (debootstrap arm64) and boot to an interactive shell over the serial console.
- Wire the real debugger image (gef/pwndbg) and the tmux `Session` (debuggee pane + debugger pane).
- Set an interactive breakpoint on a userspace-reachable function and hit it from the guest shell.
