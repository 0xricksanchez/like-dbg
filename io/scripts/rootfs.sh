#!/usr/bin/env bash
# Modified version of the syzkaller script:
#   https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
set -Eeuo pipefail
if [ "${LIKEDBG_ROOTFS_TRACE:-0}" = "1" ]; then
  set -x
fi

ROOTFS_STARTED_AT=$(date +%s)
log() {
  local now
  now=$(date +%s)
  printf '[rootfs +%ss] %s\n' "$((now - ROOTFS_STARTED_AT))" "$*"
}

# Build the chroot on the container's own (real Linux) filesystem, NOT the bind-mounted
# /io: on macOS/colima, /io is virtiofs-backed APFS where debootstrap's mknod/device-node
# operations fail. Only the final single-file image is copied out to /io at the end.
OUTDIR=/io
WORKDIR="$(mktemp -d)"
pushd "$WORKDIR" >/dev/null || exit 255
cleanup() {
  local status=$?
  popd >/dev/null 2>&1 || true
  sudo rm -rf "$WORKDIR" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

MNT=rootfs
SEEK=3071
PKGS="build-essential,clang,openssh-server,sudo,curl,tar,time,less,psmisc,openssl,file"
ARCH=$(uname -m)
DIST=bookworm
ROOTFS_NAME=rootfs
USER=user
HOSTNAME=""
export DEBIAN_FRONTEND=noninteractive

while (("$#")); do
  case "$1" in
  -a | --arch)
    # Sets the architecture
    ARCH=$2
    shift 2
    ;;
  -d | --distribution)
    # Sets the debian distribution, which defaults to bookworm right now
    DIST=$2
    shift 2
    ;;
  -s | --seek)
    # Sets the size of the file system, default 3G
    SEEK=$(($2 - 1))
    shift 2
    ;;
  -n | --name)
    # Sets the name of the rootfs
    ROOTFS_NAME=$2
    shift 2
    ;;
  -p | --packages)
    # Set packages to install
    PKGS=$2
    shift 2
    ;;
  -u | --user)
    # The non-root user
    USER=$2
    shift 2
    ;;
  -h | --hostname)
    # Hostname to set
    HOSTNAME=$2
    shift 2
    ;;
  -*)
    echo "Error: Unknown option: $1" >&2
    exit 1
    ;;
  *) # No more options
    break
    ;;
  esac
done

if [ ! "$HOSTNAME" ]; then
  if [ ! "$ROOTFS_NAME" ]; then
    HOSTNAME="LIKEDBG"
  else
    HOSTNAME="$ROOTFS_NAME"
  fi
fi

# Handle cases where qemu and Debian use different arch names
case "$ARCH" in
ppc64le)
  DEBARCH=ppc64el
  ;;
aarch64)
  DEBARCH=arm64
  ;;
arm)
  DEBARCH=armel
  ;;
x86_64)
  DEBARCH=amd64
  ;;
*)
  DEBARCH=$ARCH
  ;;
esac

ensure_binfmt() {
  local handler="qemu-$ARCH"
  local path="/proc/sys/fs/binfmt_misc/$handler"
  if [ -r "$path" ]; then
    log "binfmt handler $handler is already registered"
    return
  fi

  log "registering binfmt handler $handler"
  if [ ! -f /proc/sys/fs/binfmt_misc/register ]; then
    sudo mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc >/dev/null
  fi

  if command -v update-binfmts >/dev/null 2>&1; then
    sudo update-binfmts --enable "$handler" >/dev/null 2>&1 || true
  fi

  if [ ! -r "$path" ]; then
    if [ ! -f "qemu-binfmt-conf.sh" ]; then
      wget -q https://raw.githubusercontent.com/qemu/qemu/master/scripts/qemu-binfmt-conf.sh
      chmod 755 qemu-binfmt-conf.sh
    fi
    ./qemu-binfmt-conf.sh --qemu-suffix "-static" --qemu-path "/usr/bin" >/dev/null
  fi
}

# Foreign architecture
FOREIGN=false
if [ "$ARCH" != "$(uname -m)" ]; then
  # i386 on an x86_64 host is exempted, as we can run i386 binaries natively
  if [ "$ARCH" != "i386" ] || [ "$(uname -m)" != "x86_64" ]; then
    log "requested foreign architecture $ARCH"
    FOREIGN=true
    ensure_binfmt
  fi
fi

if [ $FOREIGN = "true" ]; then
  # Check for according qemu static binary
  QEMU_STATIC="$(command -v qemu-"$ARCH"-static || true)"
  if [ -z "$QEMU_STATIC" ]; then
    echo "Please install qemu static binary for architecture \"$ARCH\" (package 'qemu-user-static' on Debian/Ubuntu/Fedora)"
    exit 255
  fi
  # Check for according binfmt entry
  if [ ! -r /proc/sys/fs/binfmt_misc/qemu-"$ARCH" ]; then
    echo "binfmt entry /proc/sys/fs/binfmt_misc/qemu-$ARCH does not exist"
    exit 255
  fi
fi

# Clean system
log "ensuring clean work environment"
sudo rm -rf "$MNT" >/dev/null
sudo mkdir -p "$MNT" >/dev/null
sudo chmod 0755 "$MNT" >/dev/null

DEBOOTSTRAP_PARAMS=(--arch="$DEBARCH" --include="$PKGS" --components=main,contrib,non-free "$DIST" "$MNT")
if [ $FOREIGN = "true" ]; then
  DEBOOTSTRAP_PARAMS=(--foreign "${DEBOOTSTRAP_PARAMS[@]}")
fi

# riscv64 is hosted in the debian-ports repository
# debian-ports doesn't include non-free, so we exclude firmware-atheros
if [ "$DEBARCH" == "riscv64" ]; then
  DEBOOTSTRAP_PARAMS=(
    --keyring /usr/share/keyrings/debian-ports-archive-keyring.gpg
    --exclude firmware-atheros
    "${DEBOOTSTRAP_PARAMS[@]}"
    http://deb.debian.org/debian-ports
  )
fi
log "running debootstrap to create base file system"
sudo debootstrap "${DEBOOTSTRAP_PARAMS[@]}"

if [ $FOREIGN = "true" ]; then
  log "running second-stage debootstrap for non-native architecture $ARCH"
  sudo mkdir -p "$MNT$(dirname "$QEMU_STATIC")" >/dev/null
  sudo cp -a "$QEMU_STATIC" "$MNT$QEMU_STATIC" >/dev/null
  sudo chroot "$MNT" /bin/bash -c "/debootstrap/debootstrap --second-stage"
fi

log "creating non-root user $USER"
PASS=$(perl -e 'print crypt($ARGV[0], "password")' "$USER")
sudo chroot "$MNT" /bin/bash -c "groupadd -g 1000 $USER && useradd -u 1000 -g 1000 -s /bin/bash -m -p $PASS $USER" >/dev/null

if [ $FOREIGN = "true" ]; then
  sudo rm -f "$MNT$QEMU_STATIC" >/dev/null
fi

log "configuring usable defaults"
sudo sed -i '/^root/ { s/:x:/::/ }' "$MNT/etc/passwd" >/dev/null
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a "$MNT/etc/inittab" >/dev/null
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a "$MNT/etc/network/interfaces" >/dev/null
# No root (/) fstab entry: the kernel cmdline `root=` mounts it and systemd-remount-fs
# applies rw. A bogus '/dev/root' entry makes systemd drop to emergency mode.
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a "$MNT/etc/fstab" >/dev/null
# echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a "$MNT/etc/fstab"
# echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a "$MNT/etc/fstab"
echo -en "127.0.0.1\tlocalhost $ROOTFS_NAME\n" | sudo tee "$MNT/etc/hosts" >/dev/null
echo "nameserver 8.8.8.8" | sudo tee -a "$MNT/etc/resolv.conf" >/dev/null
echo "$HOSTNAME" | sudo tee "$MNT/etc/hostname" >/dev/null
dircolors -p | sudo tee "$MNT/home/$USER/.dircolors" >/dev/null
echo "export TERM=vt100" | sudo tee -a "$MNT/home/$USER/.bashrc" >/dev/null
echo "stty cols 128 rows 192" | sudo tee -a "$MNT/home/$USER/.bashrc" >/dev/null
sudo cp "$MNT/home/$USER/.bashrc" "$MNT/home/$USER/.dircolors" "$MNT/root" >/dev/null
sudo chown -R 1000:1000 "$MNT/home/$USER" >/dev/null
echo 'eval "$(dircolors ~/.dircolors)" > /dev/null' | sudo tee -a "$MNT/root/.bashrc" >/dev/null
printf "+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\nWelcome to your LIKE-DBG session :). Happy hacking!\n+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\n" | sudo tee "$MNT/etc/motd" >/dev/null
SSH_KEY="$ROOTFS_NAME.id_ed25519"
ssh-keygen -q -f "$SSH_KEY" -t ed25519 -N '' -C "root@$HOSTNAME" >/dev/null
sudo mkdir -p "$MNT/root/.ssh/" >/dev/null
cat "$SSH_KEY.pub" | sudo tee "$MNT/root/.ssh/authorized_keys" >/dev/null
sudo chmod 0700 "$MNT/root/.ssh" >/dev/null
sudo chmod 0600 "$MNT/root/.ssh/authorized_keys" >/dev/null

log "building final ext4 disk image"
truncate -s "$((SEEK + 1))M" "$ROOTFS_NAME"
sudo mkfs.ext4 -q -F -d "$MNT" "$ROOTFS_NAME"
sudo rm -rf "$MNT" >/dev/null
chmod 0644 "$ROOTFS_NAME"
chmod 0600 "$SSH_KEY"
chmod 0644 "$SSH_KEY.pub"

# Copy the finished image (sparse) and its ssh key out to the mounted output dir (/io).
log "copying image to $OUTDIR"
OUT_UID="$(stat -c %u "$OUTDIR")"
OUT_GID="$(stat -c %g "$OUTDIR")"
sudo cp --sparse=always "$ROOTFS_NAME" "$OUTDIR/$ROOTFS_NAME"
sudo cp "$SSH_KEY" "$OUTDIR/$SSH_KEY" 2>/dev/null || true
sudo cp "$SSH_KEY.pub" "$OUTDIR/$SSH_KEY.pub" 2>/dev/null || true
sudo chown "$OUT_UID:$OUT_GID" "$OUTDIR/$ROOTFS_NAME" "$OUTDIR/$SSH_KEY" "$OUTDIR/$SSH_KEY.pub" 2>/dev/null || true
sudo chmod 0644 "$OUTDIR/$ROOTFS_NAME"
sudo chmod 0600 "$OUTDIR/$SSH_KEY" 2>/dev/null || true
sudo chmod 0644 "$OUTDIR/$SSH_KEY.pub" 2>/dev/null || true
log "rootfs image complete"
