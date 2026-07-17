#!/bin/bash
# ----------------------------------------------------------------------
# (c) 2022 - 0xricksanchez <mail@0x434b.dev>
# ----------------------------------------------------------------------
set -e

GZIP=0
ENC=0
DEC=0
DEST=""

usage() {
  cat <<EOF
This script is a helper to (un-)pack rootfs.cpio(.gz) root file systems on the fly.

Usage:
    $0 -r <rootfs> [-g] (-p|-x) [-d <destination>]

    Mandatory options:
        -r <rootfs> : Path to the archive to unpack / folder housing the rootfs to pack
        -p          : Toggle if you want to re-pack a rootfs directory into a rootfs.cpio(.gz)
        -x          : Toggle if you want to unpack a rootfs.cpio(.gz) into a directory
    
    Optional flags:
        -g          : Enable gzip de-compression
        -d <dir>    : Destination folder for unpacking (default: ./initramfs)
EOF
  exit 255
}

is_exist() {
  # shellcheck disable=SC1072,1073,1009
  if [ ! "$2" "$1" ]; then
    echo "Could not find $1"
    exit 255
  fi
}

pack() {
  is_exist "$1" "-d"
  rm -f -- "$1.cpio" "$1.cpio.gz" || return 1

  pushd "$1" >/dev/null
  dst=$(basename "$1")
  if [ "$2" -eq 1 ]; then
    find . -print0 | cpio --null --format=newc -o --owner=root 2>/dev/null | gzip -9 > "../$dst.cpio.gz"
  else
    find . -print0 | cpio --null --format=newc -o --owner=root 2>/dev/null > "../$dst.cpio"
  fi
  popd >/dev/null
}

unpack() {
  if ! hash cpio 2>/dev/null; then
    echo "Couldn't find 'cpio' utility... Exiting!"
    exit 255
  fi
  is_exist "$1" "-f"
  LOCAL_ROOTFS="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
  LOCAL_DST="${DEST:-initramfs}"

  mkdir -p -- "$LOCAL_DST" || return 1
  pushd "$LOCAL_DST" >/dev/null
  echo "Unpacking $LOCAL_ROOTFS > $(pwd)"

  if [ "$2" -eq 1 ]; then

    gzip -dc "$LOCAL_ROOTFS" | cpio -idm &>/dev/null
  else
    cpio -idm <"$LOCAL_ROOTFS" &>/dev/null
  fi

  LUSER=$(logname 2>/dev/null || echo "$SUDO_USER")
  popd >/dev/null
  chown -R "$LUSER": "$LOCAL_DST" || return 1
}

if [ $# -eq 0 ]; then
  usage
fi

while true; do
  if [ $# -eq 0 ]; then
    break
  fi
  case "$1" in
  -r | --rootfs)
    # Path to rootfs, either dir to pack, or archive to unpack
    ROOTFS=$2
    shift 2
    ;;
  -g | --gzipped)
    # Is the cpio archive gzipped or should it be gzipped?
    GZIP=1
    shift 1
    ;;
  -p | --pack)
    # Toggle to pack rootfs back into a cpio
    ENC=1
    shift 1
    ;;
  -x | --extract)
    # Toggle to extract cpio rootfs
    DEC=1
    shift 1
    ;;
  -d | --destination)
    # Unpacking a .cpio(.gz) into a specific area instead of ./initramfs
    DEST=$2
    shift 2
    ;;
  -*)
    usage
    ;;
  *)
    # No more options
    break
    ;;
  esac
done

if [ "$ENC" -eq "$DEC" ]; then
  echo "Cannot pack and unpack at the same time..."
  exit 255
fi

if [ "$DEC" -eq 1 ]; then
  if [[ $UID != 0 ]]; then
    echo "Script needs to be run with sudo when unpacking as it may fail otherwise"
    exit 255
  fi
  unpack "$ROOTFS" "$GZIP" || {
    echo "Unpacking failed.."
    exit 255
  }
fi

if [ "$ENC" -eq 1 ]; then
  pack "$ROOTFS" "$GZIP" || {
    echo "Packing failed.."
    exit 255
  }
fi

echo "Success!"
