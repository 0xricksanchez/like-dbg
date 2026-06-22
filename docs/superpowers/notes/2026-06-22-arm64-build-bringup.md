# arm64 build bring-up — Task 8 live validation (2026-06-22)

First live end-to-end validation of the M1 Plan 2 build chain on the target host
(Apple M5 Pro, macOS 26.4.1, colima vz). **Result: SUCCESS** — the pipeline downloaded,
unpacked, and clang-cross-compiled a debuggable arm64 6.6.30 kernel.

## Host

- colima `vz`, 4 CPU / 8 GiB / 60 GiB, docker 29.5.2, guest = Ubuntu 24.04 arm64.
- No `/dev/kvm` in the VM (colima vz exposes none) → confirms the topology choice: arm64
  boots via **native HVF QEMU on the Mac** (Plan 3), not in-container KVM.
- binfmt (`tonistiigi/binfmt --install all`) registered linux/arm64 + linux/amd64 + linux/386.

## What ran (timings)

`HostProfile.detect` → `os=darwin accel=hvf mode=native-host storage=volume` (APFS is
case-insensitive → **volume mode**, kernel tree in the `likedbg_ksrc` Docker volume).

1. **Download** 6.6.30 (`cdn.kernel.org/.../linux-6.6.30.tar.xz`) → `<repo>/kernels/` — ~8 s.
2. **Unpack** into the `likedbg_ksrc` volume (`/ksrc/linux-6.6.30`), workspace ro at `/io` — ~17 s.
3. **Build** (clang/LLVM, `defconfig` + `debug` + `no-kaslr` + `generic` fragments, `make -j$(nproc) all`) — **~9.5 min**.

## Artifacts (verified via a container mounting the volume)

- `vmlinux` — ELF 64-bit ARM aarch64, **with debug_info, not stripped** (377 MB).
- `arch/arm64/boot/Image` — Linux kernel ARM64 boot executable, 4K pages (34 MB).
- `scripts/gdb/vmlinux-gdb.py` present + `CONFIG_DEBUG_INFO=y` → fragment merge worked; the
  kernel is GDB-debuggable (what Plan 3 needs).

## Bring-up fixes folded back into the code

1. **`ContainerService.exec` must run via a shell.** docker-py does not wrap a string `cmd`
   in a shell, so `make -j$(nproc) all` and the `merge_config.sh ... && make olddefconfig`
   step failed to evaluate `$(nproc)`/`&&`. Fixed: `exec` now runs
   `container.exec_run(["/bin/sh", "-c", cmd], ...)`. Locked by `test_exec_wraps_command_in_shell`.
2. **`.gitignore`** gained `kernels/` (download cache).

## Open items for Plan 3 (assembly)

- **Docker socket resolution (IMPORTANT).** `docker.from_env()` defaults to
  `/var/run/docker.sock` and does NOT read the docker CLI's active context, so under colima
  the Python client can't connect. The PoC worked only with
  `DOCKER_HOST=unix:///Users/krah/.colima/default/docker.sock`. The Plan 3 CLI/assembly that
  constructs the docker client must resolve the active context's socket on macOS (honor
  `DOCKER_HOST`, else read `docker context inspect <active>`), not assume the default path.
- **Volume-mode artifact export.** `vmlinux`/`Image` live in the `likedbg_ksrc` volume; native
  HVF QEMU on the Mac host can't read a Docker volume directly. Plan 3's debuggee must export
  those two single files to the bind-mounted workspace (per spec §4.6) before booting.
- `binfmt_arm64()` in `bootstrap.py` is still a docker-presence proxy (the live run shows the
  real handlers are registered; refine the probe to check actual qemu-aarch64 binfmt).
- `no-kaslr` fragment applied (merge ran); confirm `# CONFIG_RANDOMIZE_BASE is not set` in the
  final `.config` when KASLR-off matters for a debugging session.
