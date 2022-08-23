#!/bin/bash

GZIP=0
ENC=0
DEC=0

pack () {
  # TODO
  # Compress initramfs with the included statically linked exploit
  in=$1
  out=$(echo $in | awk '{ print substr( $0, 1, length($0)-2 ) }')
  gcc $in -static -o $out || exit 255
  mv $out initramfs
  pushd . && pushd initramfs
  find . -print0 | cpio --null --format=newc -o 2>/dev/null | gzip -9 > ../initramfs.cpio.gz
  popd
}

unpack () {
  mkdir initramfs
  pushd . && pushd initramfs
  cp ../"$1" .
  # $2 will be toggle for gzip
  gzip -dc initramfs.cpio.gz | cpio -idm &>/dev/null && rm initramfs.cpio.gz
  popd
}

while true; do
    if [ $# -eq 0 ];then
	echo $#
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
          shift 2
          ;;
        -p | --pack)
          # Toggle to pack rootfs back into a cpio
          ENC=1
          shift 2
          ;;
        -x | --extract)
          # Toggle to extract cpio rootfs
          DEC=1
          shift 2
          ;;
        -*)
          echo "Error: Unknown option: $1" >&2
          exit 1
          ;;
        *)  
          # No more options
          break
          ;;
    esac
done

if [ "$ENC" -eq "$DEC" ]; then
  echo "Cannot pack and unpack at the same time..."
  exit -1
fi

# TODO IF-ELSE function call depending in toggles
