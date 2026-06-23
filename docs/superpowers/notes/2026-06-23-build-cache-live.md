# M1 Plan 5 — Build Cache: live boot+attach gate (2026-06-23)

Empirical exit gate for the build-reuse cache (and the deferred Plan-4 Task 5).
Host: Apple Silicon macOS, colima (4 CPU / 8 GB), volume storage mode, native HVF QEMU.

## Result: PASS — one command, zero kernel rebuild, GEF at `start_kernel`

`./start_kgdb` inside tmux drove the full pipeline with the kernel build **reused from
cache** (no `make`), booted the kernel natively under HVF, and attached GEF:

- **Cache hits (instant, same timestamp):** `download`, `unpack`, `build` all completed at
  `12:36:02` — the kernel was **not** rebuilt. `rootfs` and `export` were also cache hits.
- **Debuggee (pane 2):** native `qemu-system-aarch64 -M virt -cpu host -accel hvf … -S -s`
  booted to a `root@LIKE-DBG:~#` shell (the rootfs boots end-to-end).
- **Debugger (pane 3):** GEF attached over `host.docker.internal:1234`, hit the
  `hbreak start_kernel` hardware breakpoint:
  ```
  ●→ 0xffff800081ad03d4 <start_kernel+0014> ...
  [#0] Id 1, stopped … in start_kernel (), reason: BREAKPOINT
  [#0] start_kernel() ← [#1] __primary_switched()
  ```
  After `continue` the kernel boots fully and remains inspectable (idle loop:
  `do_idle ← cpu_startup_entry ← rest_init ← arch_call_rest_init`).

## Cache state after `--adopt` + seed

- Build: `artifacts/cache/builds/linux-6.6.30-35e79946.json` — adopted from the existing
  unkeyed `/ksrc/linux-6.6.30` via `./start_kgdb --adopt` (verified clang 18.1.3 / 6.6.30),
  renamed in-volume to `/ksrc/linux-6.6.30-35e79946`. **No rebuild.**
- Rootfs: `artifacts/cache/rootfs/rootfs-arm64-bookworm-1c5f217c.json` — see caveat below.

## Wiring fixes folded back (surfaced by the gate)

1. **tmux `pane-base-index`** (`session.py`): `open_debug_layout` hardcoded `select_pane(0)`
   and `return (1,2)`; this host uses `pane-base-index 1`, so the very first `selectp -t 0`
   failed. Now queries the base index and computes `base, base+1, base+2`. (commit 88a7d0a)
2. **Manifest dir pluralization** (`cache.py`): `manifest_path` used `f"{kind}s"`, sending
   rootfs manifests to `cache/rootfss/` (double-s). Mapped `kind → {build:builds, rootfs:rootfs}`
   per spec §4.3. (commit a5cc6b9)
3. **RootfsStage silent failure** (`stages/rootfs.py`): it wrote a manifest without checking
   the build actually produced the image, so a failed build yielded a bogus "cached" entry
   and QEMU later died on a missing `-drive` file. Now raises `RootfsError` if the image is
   absent after the build. (commit a5cc6b9)
4. **Debugger locale** (`.dockerfile_dbg`): GEF threw `UnicodeEncodeError: '➤'` under the
   container's ascii stdout. Added `ENV LANG/LC_ALL=C.UTF-8` and rebuilt `like_debugger`. (562e1ea)

## Caveat: fresh rootfs.sh build (separate, pre-existing — NOT a cache defect)

The legacy `io/scripts/rootfs.sh` debootstrap build did **not** emit a `.img` for `bookworm`
in this run (it exited in ~37s leaving a partial chroot, no image). This is a rootfs-builder
issue independent of the Plan-5 cache and is now caught loudly by fix #3 above (no bogus
manifest). For this gate the rootfs was **adopted** from the known-good Plan-3 image
(`artifacts/rootfs-arm64.img`) copied to the keyed path + a correct manifest — the same
"reuse an existing artifact" story as `--adopt` for the kernel. The `start_kernel` gate does
not depend on rootfs contents, and the adopted rootfs in fact boots to a shell. **Follow-up
(separate from Plan 5):** fix `rootfs.sh` fresh builds (bookworm / aarch64 emulation), or add
a `--adopt-rootfs` analogue.

## Addendum (2026-06-23): dual debugger extensions (gef + pwndbg)

The debugger image now installs BOTH GEF (`/opt/gef/gef.py`) and pwndbg
(`git clone + setup.sh` → `/opt/pwndbg/gdbinit.py`); `~/.gdbinit` auto-loads neither
(pwndbg's setup.sh auto-source line is stripped). `build_gdb_args` sources the requested
extension via `-iex source <path>` so config `[debugger] ext = gef|pwndbg` actually selects
it. `PWNDBG_NO_AUTOUPDATE=1` keeps launches offline/fast.

Both validated live via the one command (cache hits → HVF boot → attach at `start_kernel`):
- `ext = gef`  → `gef➤`, stopped at `start_kernel` (BREAKPOINT), bt `start_kernel ← __primary_switched`.
- `ext = pwndbg` → `pwndbg>`, DISASM/STACK/BACKTRACE at `start_kernel+20`, bt `start_kernel ← __primary_switched`.
