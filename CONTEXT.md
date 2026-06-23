# LIKE-DBG

A fully containerized Linux kernel debugging environment: it builds (or ingests) a kernel
and root filesystem, boots them under emulation, and attaches an interactive debugger,
wiring everything into a single tmux session.

## Language

### Debugging session

**Debuggee**:
The emulated guest under inspection — a specific kernel image together with its root
filesystem, booted under QEMU and exposing a stub for inspection. The composition, at boot,
of one Kernel Build and one rootfs image.
_Avoid_: guest, VM, target.

**Debugger**:
The interactive GDB session (driven by GEF or pwndbg) attached to the debuggee's stub.
_Avoid_: gdb session, client.

**CTF context**:
A run where the kernel image and root filesystem are supplied ready-made (a challenge),
rather than downloaded and built from source.
_Avoid_: challenge mode, ctf mode.

### Build cache

**Kernel Build**:
A compiled kernel — its tree and the consumable artifacts it yields — produced from one
specific configuration and kept for reuse instead of rebuilt. Half of a Debuggee (the
rootfs image is the other half).
_Avoid_: build (the verb/stage), image.

**Label**:
The human-readable identifier of one cached artifact (a Kernel Build or a rootfs image),
e.g. `linux-6.6.30-gef-a1b2c3d4`.
_Avoid_: tag, id, name.

**Manifest**:
The host-side record of one cached artifact — its label, configuration identity, and where
it lives — and the source of truth for what is cached.
_Avoid_: index, metadata.

**Build Cache**:
The collection of reusable Kernel Builds and rootfs images, keyed by configuration so an
identical configuration is never rebuilt.
_Avoid_: store, cache store.

**Storage mode**:
Whether the kernel source tree is host-visible. In **Bind mode** the tree is host-editable;
in **Volume mode** it is off-host (the zero-setup default on case-insensitive filesystems).
Chosen automatically and recorded on every Manifest; governs where a Kernel Build lives and
how it is reached. See ADR-0002 for the mechanism.
_Avoid_: naming the concept after the `storage_mode` field; mount type.
