#!/bin/bash
# ----------------------------------------------------------------------
# (c) 2022      <admin@0x434b.dev>
# ----------------------------------------------------------------------
set -e

GZIP=0
ENC=0
DEC=0
EXPLOIT=
MUSL=$(which musl-gcc)

usage() {
    cat << EOF
This script is a helper to (un-)pack rootfs.cpio(.gz) root file systems on the fly.

Usage:
    $0 [-r [rootfs]] [-g] [-p|-x] [-e [exploit]]

    Mandatory options:
        -r <rootfs> : Path to the archive to unpack / folder housing the rootfs to pack
        -p          : Toggle if you want to re-pack a rootfs directory into a rootfs.cpio(.gz)
        -x          : Toggle if you want to unpack a rootfs.cpio(.gz) into a directory
    
    Optional flags:
        -g          : Enable gzip de-compression
        -e          : Provide a path to an exploit.c in a rootfs directory to statically compile it with musl-gcc
EOF
}

is_exist() {
    if [ ! "$2" "$1" ]; then
        echo "Could not find $1"
        exit 255
    fi
}

pack() {
    is_exist "$1" "-d"
    is_exist "$3" "-f"

    if [ -n "$3" ]; then
        is_exist "$MUSL" "-f"
        out=$(echo "$3" | awk '{ print substr( $0, 1, length($0)-2 ) }')
        musl-gcc "$3" -static -o "$out" || exit 255
    fi

    pushd . && pushd "$1"
    cmd="find . -print0 | cpio --null --format=newc -o --owner=root 2>/dev/null"
    if [ "$2" -eq 1 ]; then
        cmd="${cmd} | gzip -9 > ../$1.cpio.gz"
    else
        cmd="${cmd} > ../$1.cpio"
    fi
    eval "$cmd"
    popd
}

unpack() {
    mkdir initramfs
    pushd . && pushd initramfs
    cp ../"$1" .

    if [ "$2" -eq 1 ]; then
        gzip -dc "$1" | cpio -idm &
        > /dev/null
    else
        cpio -idm < "$1" &
        > /dev/null
    fi

    rm "$1"
    popd
}

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
        -e | --exploit)
            # If you want to compile your exploit before packing, you can provide a path here
            EXPLOIT=$2
            shift 2
            ;;
        -*)
            usage
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
    exit 255
fi

if [ "$DEC" -eq 1 ]; then
    unpack "$ROOTFS" "$GZIP"
fi

if [ "$ENC" -eq 1 ]; then
    pack "$ROOTFS" "$GZIP" "$EXPLOIT"
fi
