#!/bin/bash
# ----------------------------------------------------------------------
# (c) 2022 - 0xricksanchez <admin@0x434b.dev>
# ----------------------------------------------------------------------
set -e

GZIP=0
ENC=0
DEC=0
EXPLOIT=

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
    exit 255
}

is_exist() {
    if [ ! "$2" "$1" ]; then
        echo "Could not find $1"
        exit 255
    fi
}

compile_mac() {
    CTR=0
    while true; do
        if [ $(basename $PWD) != "like-dbg" ] || [ ! -f "$(pwd)/.dockerfile_base" ]; then
            pushd .. > /dev/null
            ((CTR++))
        else
            break
        fi

    done
    if [ ! $(docker images | grep -o "like_mac_compiler") ]; then
        docker build -t "like_mac_compiler" -f .dockerfile_compiler_mac .
    fi
    while [ $CTR -ne 0 ]; do
        popd > /dev/null
        ((CTR--))
    done
    rsync -u $2 $1/root/ > /dev/null
    out="/io/bin/$(basename $2)"
    out=${out%.*}
    docker run --rm -v "$(pwd)/$1":/io "like_mac_compiler" musl-gcc /io/root/$(basename $2) -static -o "$out"
}

pack() {
    is_exist "$1" "-d"

    if [ -n "$3" ]; then
        is_exist "$3" "-f"
        if [ $(uname -s) == "Darwin" ]; then
            compile_mac $1 $3
        else
            MUSL=$(which musl-gcc)
            is_exist "$MUSL" "-f"
            out=$(echo "$3" | awk '{ print substr( $0, 1, length($0)-2 ) }')
            $MUSL "$3" -static -o "$out" || exit 255
            mv "$out" "$1/bin/"
        fi
        echo "Exploit pushed to $1/bin/"
    fi
    rm -rf "$1.cpio" "$1.cpio.gz"

    pushd . > /dev/null && pushd "$1" > /dev/null
    cmd="find . -print0 | cpio --null --format=newc -o --owner=root 2>/dev/null"
    dst=$(basename "$1")
    if [ "$2" -eq 1 ]; then
        cmd="${cmd} | gzip -9 > ../$dst.cpio.gz"
    else
        cmd="${cmd} > ../$dst.cpio"
    fi
    eval "$cmd"
    popd > /dev/null
}

unpack() {
    mkdir initramfs
    pushd . > /dev/null && pushd initramfs > /dev/null
    cp ../"$1" .
    LOCAL_ROOTFS="$(pwd)/$(basename $1)"

    if [ "$2" -eq 1 ]; then
        gzip -dc "$LOCAL_ROOTFS" | cpio -idm &> /dev/null
    else
        cpio -idm < "$LOCAL_ROOTFS" &> /dev/null
    fi

    rm "$LOCAL_ROOTFS"
    LUSER=$(logname 2> /dev/null || echo $SUDO_USER)
    popd > /dev/null
    chown -R $LUSER: initramfs
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
        -e | --exploit)
            # If you want to compile your exploit before packing, you can provide a path here
            EXPLOIT=$2
            shift 2
            ;;
        -*)
            usage
            exit 255
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
    unpack "$ROOTFS" "$GZIP"
fi

if [ "$ENC" -eq 1 ]; then
    pack "$ROOTFS" "$GZIP" "$EXPLOIT"
fi

echo "Success!"
