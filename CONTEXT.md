# LIKE-DBG

A fully containerized Linux kernel debugging environment: it builds (or ingests) a kernel
and root filesystem, boots them under emulation, and attaches an interactive debugger,
wiring everything into a single tmux session.

## Language

**Debuggee**:
The emulated guest under inspection — a specific kernel image together with its root
filesystem, booted under QEMU and exposing a stub for inspection.
_Avoid_: guest, VM, target.

**Debugger**:
The interactive GDB session (driven by GEF or pwndbg) attached to the debuggee's stub.
_Avoid_: gdb session, client.

**CTF context**:
A run where the kernel image and root filesystem are supplied ready-made (a challenge),
rather than downloaded and built from source.
_Avoid_: challenge mode, ctf mode.
