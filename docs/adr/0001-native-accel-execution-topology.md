# Native-acceleration execution topology

On macOS, QEMU runs **natively on the host** with HVF (arm64 only) while build, rootfs, and
debugger stay containerized; on Linux, QEMU runs **in-container** with `/dev/kvm`. The
debugger is always containerized (for a reproducible gdb + GEF/pwndbg) and attaches to the
QEMU gdbstub **over TCP** — `host.docker.internal:1234` on macOS, localhost/shared-net on
Linux — and artifacts cross the host/container boundary via explicit
`(host_path, container_path)` pairs anchored on one `workspace_dir`.

We chose this over (a) fully-dockerized QEMU everywhere (a Linux container can't reach
macOS HVF → slow TCG arm64 on the Mac) and (b) fully-native QEMU **and** gdb (host pollution
plus painful, poorly-supported `gdb-multiarch`/GEF/pwndbg on macOS). This delivers fast
arm64-by-default on the Mac while keeping the messy toolchain dockerized and the debugger
reproducible.

Native QEMU fires **only** for the accelerated same-arch case (arm64-on-arm-Mac);
x86_64-on-Mac stays in-container TCG, so the debuggee container image remains in use on
macOS. This also retires the previous `--net=host` + `--pid=container` coupling, which did
not work cleanly off Linux.
