# Case-sensitive workspace storage (bind vs. volume)

The Linux kernel source tree contains files that differ only by case (e.g. `xt_CONNMARK`
vs `xt_connmark`), which a default **case-insensitive APFS** volume silently corrupts on
unpack. The framework therefore auto-selects storage instead of requiring users to manage
case-sensitive volumes:

- **Bind mode** — when `workspace_dir` is on case-sensitive storage (Linux always; macOS if
  available). Source is bind-mounted and host-editable.
- **Volume mode** — the zero-setup macOS default when `workspace_dir` is case-insensitive.
  The kernel tree and rootfs chroot live in a **Docker named volume on colima's (natively
  case-sensitive) ext4**; only the single-file consumables (kernel `Image` + rootfs image,
  which cannot collide) are exported to the APFS workspace for native QEMU. The debugger
  container mounts the source volume read-only.

We rejected **mandating a case-sensitive APFS volume** (too invasive/painful for a tool
meant to be frictionless — and colima is already a hard dependency we can lean on) and
rejected **ignoring the issue** (corrupted, unbuildable trees on every Mac). The trade-off:
in volume mode the source tree is not visible to the host editor — mitigated because power
users can opt into bind mode via a case-sensitive volume, and `custom_modules`/patches are
applied as host inputs into the in-volume tree.
