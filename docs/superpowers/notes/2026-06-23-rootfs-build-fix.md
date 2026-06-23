# Rootfs fresh-build fix — diagnosis + fix (2026-06-23)

## Symptom
A fresh `RootfsStage` build (the Plan-5 live gate, and any `./start_kgdb` without a cached
rootfs) produced **no `.img`** — the build container exited in ~37s leaving a partial
debootstrap chroot. Plan 5's RootfsStage now raises `RootfsError` on the missing image, so it
failed loudly; the live gates used an *adopted* rootfs to work around it.

## Root cause (systematic-debugging)
The `like_rootfs:latest` **image was stale**. `diff`-ing the in-image `/home/user/rootfs.sh`
against the working tree showed the image carried the *old* script (`pushd /io`, `/dev/root`
fstab, no copy-to-OUTDIR step). The old script builds the debootstrap chroot **directly in the
bind-mounted `/io`** — which on macOS/colima is virtiofs-backed APFS where `mknod` device-node
creation fails, so debootstrap aborts and no image is produced.

`io/scripts/rootfs.sh` had **already been fixed in source** (Plan 3: build the chroot in a
container-local `mktemp` dir, copy only the final image out to `/io`). But nothing ever rebuilt
the image: `ContainerService.build_image` exists yet is **never called** anywhere in the
package, and the justfile had no image-build step. So the source fix never reached the running
image — a stale-image class of bug.

## Fix
1. **Rebuilt `like_rootfs:latest`** from the current `rootfs.sh` (on the existing 24.04 base).
   No `rootfs.sh` change was needed — it was already correct.
2. **Added `just build-images`** — (re)builds all four images (base → kbuilder, rootfs,
   debugger) from the current dockerfiles in dependency order, so a source change can't silently
   leave a stale image. Documented: run it after changing any `.dockerfile_*` or baked-in
   `io/scripts/*`.

## Verification (real pipeline, not just raw docker)
Cleared the rootfs cache and ran `./start_kgdb`: kernel build **cache-hit**, rootfs built
**fresh in ~60s** (valid 3.2 GB ext4), exported, booted native HVF, and `gef` stopped at
`start_kernel` (bt `start_kernel ← __primary_switched`). QEMU booted the freshly-built
`rootfs-arm64-bookworm-1c5f217c.img`. Fresh rootfs builds now work end-to-end; adoption is no
longer required.

## Note
`.dockerfile_base` has an uncommitted local bump to `ubuntu:26.04`; this fix deliberately kept
the existing 24.04 base (rebuilt only `like_rootfs`). `just build-images` will pick up whatever
the dockerfiles say when run.
