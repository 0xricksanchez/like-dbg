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

**Debuggee mode**:
Where the Debuggee's QEMU runs. **Native-host**: QEMU as a host process (macOS, same architecture,
hardware-accelerated). **In-container**: QEMU inside the debuggee Container image (Linux, or
x86_64-on-Mac under emulation). Chosen automatically from the host and guest architecture (see
ADR-0001) and recorded on the host profile; together with Network mode it governs how the
Debugger reaches the gdbstub.
_Avoid_: confusing it with Storage mode (a separate axis — where the kernel *source* lives);
naming the concept after the `debuggee_mode` field.

**Network mode**:
How the Debugger reaches the Debuggee's gdbstub across the container boundary. **Host**: the
Debuggee shares the host network, so the stub is reached on `localhost` with no gateway hop
(the Linux default). **Published**: the Debuggee publishes the stub's port and the Debugger
reaches it through the Docker gateway at `host.docker.internal` (the macOS default — and the
only option when QEMU is a host process or Docker offers no host networking). Auto-selected
per host, overridable, and the stub's port is configurable. See ADR-0001.
_Avoid_: naming the concept after the `network` field; conflating it with Debuggee mode
(*where* QEMU runs) — Network mode is *how the Debugger connects*, a separate axis.

**Debugger**:
The interactive GDB session (driven by GEF or pwndbg) attached to the debuggee's stub.
_Avoid_: gdb session, client.

**Debug profile**:
A TOML-backed named debugging intent that resolves to build-time kernel configuration fragments, expected
post-build `.config` checks, optional boot arguments, runtime defaults, and operator warnings. A Debug
profile answers "what kind of kernel/debugging experience are we building for?" Examples include
`exploit-dev`, `hardened`, `crash-debug`, and sanitizer profiles. Runtime Debuggee settings may only
override behavior the built kernel actually supports; contradictions are errors, and explicit
user/scenario/CLI config wins over profile-provided runtime defaults by provenance.
_Avoid_: using it to mean a cached Kernel Build, a GDB extension choice, or a loose preset that
silently overrides unrelated config.

**CTF context**:
A run where the kernel image and root filesystem are supplied ready-made (a challenge),
rather than downloaded and built from source.
_Avoid_: challenge mode, ctf mode.

**Run artifact**:
The durable record of one attempted interactive Debugging session under `artifacts/runs/<run-id>/`.
It includes requested/effective settings, Debug profile resolution, command records, logs/transcripts,
kernel config snapshots, and status. Failed pre-boot verification still creates a Run artifact.
The run status set is: `created` → `profile-verification-failed` | `launching` → `launched`
[→ `crashed`] | `launch-failed`. `crashed` is set post-hoc by Crash intelligence when it detects a
fatal fault (B3); run-completion/exit states belong to later B5 work.
_Avoid_: using it for cache-management events such as `--adopt`, `--clean`, or image rebuilds.

**Console log**:
The byte-exact capture of the Debuggee's serial console for one run (`console.raw`), teed straight
from QEMU into the Run artifact. Distinct from the operator-pane transcript: the Console log is pure
guest serial output — the source of truth for crash parsing and a clean boot record.
_Avoid_: serial dump; pane transcript (that is the tmux operator-pane capture, a separate thing).

**Crash report**:
The durable, symbolized record of a Debuggee fault within a Run artifact (`crash.json` + `crash.md`),
built from the Console log and enriched by the Debugger's live state when it halted at the fault. One
report may hold several crash events; the first fatal one is primary.
_Avoid_: crash dump, oops log, core dump.

**Guest share**:
The 9p-backed live directory shared between the host and the running Debuggee — a persistent host
`exploit/` dir mounted read-write at `/mnt/exploit`. Edits and the exploit's output are visible on both
sides as they are written, so artifacts survive a kernel panic.
_Avoid_: shared folder, 9p mount, virtfs.

**Exploit run**:
One `start_kgdb --run` against the live Debuggee: the exploit is delivered (in place via the Guest share,
else copied over SSH), executed over SSH, its stdout/stderr and artifacts captured into the Run artifact,
and a Crash report produced if it faults the kernel.
_Avoid_: exploit session, payload run.

**Custom module**:
An out-of-tree kernel module (a `custom_modules` entry: a source dir with an `obj-m` Makefile, or a
prebuilt `.ko`) built against the running session's kernel and loaded into the live Debuggee. The `.ko` is
staged in the Guest share (`/mnt/exploit/modules/`) and loaded on command with `start_kgdb --insmod`
(`rmmod`-then-`insmod` to reload) — never auto-loaded at boot, so gdb can be armed before the module's
`init` runs. Typically the vulnerable driver an Exploit run then targets.
_Avoid_: in-tree module, driver injection, kernel patch.

**Module build**:
The out-of-tree compile of a Custom module — `make -C /ksrc/<label> M=<src> modules` in the kbuilder
container against the already-built kernel tree, using the Kernel Build's toolchain env (`ARCH`, `LLVM`) so
vermagic/ABI match. Runs as a boot-time stage over all `custom_modules` and on demand (build-if-stale) via
`--insmod`. Does **not** rebuild or invalidate the Kernel Build.
_Avoid_: recompiling the kernel; "module compile" (say Module build).

**Foreign kernel**:
A kernel like-dbg did **not** build — a provided (CTF/triage) `bzImage`/`Image` + `vmlinux` + `initramfs`,
declared in a `[foreign]` scenario config with the challenge's authoritative boot `cmdline`. `start_kgdb -c
<challenge>` adopts it Manifest-free: bypasses Download/Unpack/Build, skips profile verification (no
`.config`), auto-detects the arch from the `vmlinux` ELF, and boots it under gdb with the provided `vmlinux`
for symbols and an interactive serial console. Has no `/ksrc` tree and no like-dbg rootfs, so 2a's SSH/9p
transport and `--run`/`--insmod` do not apply.
_Avoid_: adopted kernel, imported kernel; conflating with `--adopt` (which migrates a source tree).

**Initramfs repack**:
The exploit-delivery path for a Foreign kernel: unpack the provided `initramfs.cpio(.gz)`, compile the
exploit static (musl) or drop a prebuilt static binary at `/exploit`, and repack — done in the standalone
`like_musl` container (no host root/`cpio`/`musl`). A live **console-upload** (base64 over the serial) is the
optional no-reboot alternative when the guest supports it. The exploit is **always run manually** from the
guest console — never auto-run.
_Avoid_: cpio rebuild, "repack the rootfs" (a Foreign kernel has an initramfs, not the Debian rootfs).

**Effective settings**:
The runtime Debuggee toggles LIKE-DBG actually uses after the 6-layer precedence merge — built-in <
project default < profile runtime defaults < local < scenario < CLI. Held as
`RunResolution.effective_debuggee` (a full `DebuggeeCfg`); QEMU/GDB read it, never the frozen
requested `Settings`. Surfaced as `settings.effective.json` in the Run artifact.
_Avoid_: mutating `Settings`; calling profile defaults "overrides" (they are the lowest non-default layer).

**Configuration provenance**:
The winning layer recorded per `(section, key)` by the TOML loader, surfaced in
`settings.effective.json` and `--explain-config`. Internal/debuggable state — users see only three
layers (project defaults, local/scenario, CLI); all six layers are available for artifact inspection
and automated tooling. _Avoid_: exposing all six layers in everyday UX.

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

### Container images

**Container image**:
One of the project's Docker build artifacts — `like_dbg_base` and the images built from it
(kbuilder, rootfs, debugger, and the debuggee) — produced from the repo's `.dockerfile_*`
files and kept current as a set. A Container image's Docker **tag** (e.g. `like_dbg_base:latest`)
and its Docker **labels** are mechanisms of the image itself, distinct from a Kernel Build's
consumable `Image` and from the cache's **Label**/**Manifest**.
_Avoid_: conflating a Container image with a Kernel Build's `Image`; calling its Docker
tag/label a cache "Label".
