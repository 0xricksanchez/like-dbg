"""Shared infrastructure literals: image tags, the kernel-source volume, and its mount.

These name the project's Docker images and the named volume that holds kernel source in
Volume mode (see CONTEXT.md -> Storage mode, ADR-0002). They are infra identifiers, not
user configuration, so they live here rather than in the Pydantic Settings schema.
"""

KERNEL_VOLUME = "likedbg_ksrc"
VOLUME_MOUNT = "/ksrc"

# Persistent ccache store shared across builds (Task 7); mounted at /ccache in the kbuilder
# container only when settings.build.ccache is enabled (see stages/build.py).
LIKEDBG_CCACHE_VOLUME = "likedbg_ccache"

BASE_IMAGE = "like_dbg_base:latest"
# NOTE: the kbuilder image is clang-universal (cross-compiles any arch); the `_arm64`
# suffix is a legacy misnomer. Revisit the name when x86_64-on-Mac lands (ROADMAP section B).
KBUILDER_IMAGE = "like_kbuilder_arm64:latest"
ROOTFS_IMAGE = "like_rootfs:latest"
DEBUGGER_IMAGE = "like_debugger:latest"
# The debuggee image runs QEMU in-container (Linux KVM, or x86_64-on-Mac TCG). Spelled out
# to avoid confusion with the like_debugger image; built from .dockerfile_dbge.
DEBUGGEE_IMAGE = "like_debuggee:latest"

# Standalone musl image: cpio + decompressors + cross-musl toolchains for BOTH arches.
# Runs as root (cpio -idm needs device nodes). Repacks the foreign initramfs, cross-compiles
# the exploit to the foreign arch, and carves vmlinux from a bzImage.
MUSL_IMAGE = "like_musl:latest"

# Pinned vmlinux-to-elf: kallsyms symbol recovery for adopted (CTF/foreign) kernels. Lives ONLY in
# the like_musl image and is invoked as a subprocess (GPL-3.0, never imported into like-dbg's MIT
# code; see ADR-0015). Threaded into the image build AND stamped into the foreign vmlinux cache, so
# bumping it both rebuilds the image and invalidates stale recoveries.
V2E_VERSION = "1.3.6"

CRASH_DROP_MOUNT = "/likedbg-crash"
DEBUGINFOD_CACHE_MOUNT = "/debuginfod-cache"  # container path for the persistent debuginfod cache
EXPLOIT_MOUNT = "/exploit"
