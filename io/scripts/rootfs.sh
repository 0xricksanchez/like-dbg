#!/usr/bin/env bash

IMG=fs.qcow2
MNT='/tmp/rootfs'

cd /io && \
ROOT_PASSWD=$(openssl passwd -1 root) && \
qemu-img create $IMG 5g && \
mkfs.ext2 $IMG && \
mkdir $MNT && \
mount -o loop $IMG $MNT && \
debootstrap --arch amd64 --include=build-essential,vim,openssh-server,make,sudo bullseye $MNT && \
sed -i -e "s#root:\*#root:${ROOT_PASSWD_HASH}#" $MNT/etc/shadow && \
umount $MNT && \
rmdir $MNT && chmod 777 $IMG 
