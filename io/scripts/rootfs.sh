#!/usr/bin/env bash
# Modified version of the syzkaller script:
#   https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
# -e exit on error
# -u Write to stderr when trying to expand a variable that does not exist
# -x Write to stderr for tracing
set -eux

# Check if binfmt_misc is ready to go
if [ ! -f /proc/sys/fs/binfmt_misc/register ]; then
    mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
fi
# Reset any qemu handlers...
find /proc/sys/fs/binfmt_misc -type f -name 'qemu-*' -exec sh -c 'echo -1 > $1' shell {} \;

# Grab qemu binfmt register script
wget https://raw.githubusercontent.com/qemu/qemu/master/scripts/qemu-binfmt-conf.sh &&
    chmod 777 qemu-binfmt-conf.sh &&
    ./qemu-binfmt-conf.sh --qemu-suffix "-static" --qemu-path "/usr/bin"

pushd /io

MNT=rootfs
SEEK=2047
PKGS="build-essential,openssh-server,sudo,curl,tar,time,less,psmisc,openssl,plymouth,file"
ARCH=$(uname -m)
DIST=bullseye
ROOTFS_NAME=rootfs
USER=user

while true; do
    if [ $# -eq 0 ]; then
        echo $#
        break
    fi
    case "$1" in
        -a | --arch)
            # Sets the architecture
            ARCH=$2
            shift 2
            ;;
        -d | --distribution)
            # Sets the debian distribution, which defaults to bullseye right now
            DIST=$2
            shift 2
            ;;
        -s | --seek)
            # Sets the size of the file system, default 5G
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
        -*)
            echo "Error: Unknown option: $1" >&2
            exit 1
            ;;
        *) # No more options
            break
            ;;
    esac
done

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

# Foreign architecture
FOREIGN=false
if [ "$ARCH" != "$(uname -m)" ]; then
    # i386 on an x86_64 host is exempted, as we can run i386 binaries natively
    if [ "$ARCH" != "i386" ] || [ "$(uname -m)" != "x86_64" ]; then
        FOREIGN=true
    fi
fi

if [ $FOREIGN = "true" ]; then
    # Check for according qemu static binary
    if ! which qemu-"$ARCH"-static; then
        echo "Please install qemu static binary for architecture $ARCH (package 'qemu-user-static' on Debian/Ubuntu/Fedora)"
        exit 1
    fi
    # Check for according binfmt entry
    if [ ! -r /proc/sys/fs/binfmt_misc/qemu-"$ARCH" ]; then
        echo "binfmt entry /proc/sys/fs/binfmt_misc/qemu-$ARCH does not exist"
        exit 1
    fi
fi

# Clean system
sudo rm -rf $MNT
sudo mkdir -p $MNT
sudo chmod 0755 $MNT

# 1. debootstrap stage
DEBOOTSTRAP_PARAMS="--arch=$DEBARCH --include=$PKGS --components=main,contrib,non-free $DIST $MNT"
if [ $FOREIGN = "true" ]; then
    DEBOOTSTRAP_PARAMS="--foreign $DEBOOTSTRAP_PARAMS"
fi

# riscv64 is hosted in the debian-ports repository
# debian-ports doesn't include non-free, so we exclude firmware-atheros
if [ "$DEBARCH" == "riscv64" ]; then
    DEBOOTSTRAP_PARAMS="--keyring /usr/share/keyrings/debian-ports-archive-keyring.gpg --exclude firmware-atheros $DEBOOTSTRAP_PARAMS http://deb.debian.org/debian-ports"
fi
#sudo debootstrap $DEBOOTSTRAP_PARAMS
eval "sudo debootstrap $DEBOOTSTRAP_PARAMS"

# 2. debootstrap stage: only necessary if target != host architecture
if [ $FOREIGN = "true" ]; then
    sudo cp -av "$(which qemu-"$ARCH"-static)" "$MNT$(which qemu-"$ARCH"-static)"
    sudo chroot $MNT /bin/bash -c "/debootstrap/debootstrap --second-stage"
fi

# 3. Create a non-root user
PASS=$(perl -e 'print crypt($ARGV[0], "password")' "$USER")
sudo chroot $MNT /bin/bash -c "groupadd -g 1000 $USER && useradd -u 1000 -g 1000 -s /bin/bash -m -p $PASS $USER"

if [ $FOREIGN = "true" ]; then
    rm -rf "$MNT$(which qemu-"$ARCH"-static)"
fi

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' $MNT/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $MNT/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $MNT/etc/network/interfaces
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $MNT/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $MNT/etc/fstab
# echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $MNT/etc/fstab
# echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $MNT/etc/fstab
if [ $FOREIGN = "false" ]; then
    echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $MNT/etc/fstab
fi
echo -en "127.0.0.1\tlocalhost $ROOTFS_NAME\n" | sudo tee $MNT/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $MNT/etc/resolve.conf
echo "$ROOTFS_NAME" | sudo tee $MNT/etc/hostname
dircolors -p > $MNT/home/"$USER"/.dircolors
echo "export TERM=vt100" >> $MNT/home/"$USER"/.bashrc
echo "stty cols 128 rows 192" >> $MNT/home/"$USER"/.bashrc
cp $MNT/home/"$USER"/.bashrc $MNT/home/"$USER"/.dircolors $MNT/root
echo 'eval "$(dircolors ~/.dircolors)" > /dev/null' >> $MNT/root/.bashrc
printf "+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\nWelcome to your LIKE-DBG session :). Happy hacking!\n+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\n" > $MNT/etc/motd
yes | ssh-keygen -f "$ROOTFS_NAME.id_rsa" -t rsa -N ''
sudo mkdir -p $MNT/root/.ssh/
cat "$ROOTFS_NAME.id_rsa.pub" | sudo tee $MNT/root/.ssh/authorized_keys > /dev/null

# Build disk image
dd if=/dev/zero of="$ROOTFS_NAME" bs=1M seek=$SEEK count=1
sudo mkfs.ext4 -F "$ROOTFS_NAME"
sudo mkdir -p /mnt/$MNT
sudo mount -o loop "$ROOTFS_NAME" /mnt/$MNT
sudo cp -a $MNT/. /mnt/$MNT/.
sudo umount /mnt/$MNT
sudo rm -rf "$MNT"
find "$ROOTFS_NAME"* -print0 | xargs -0 chmod 0755
