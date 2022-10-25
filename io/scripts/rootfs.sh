#!/usr/bin/env bash
# Modified version of the syzkaller script:
#   https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh

pushd /io > /dev/null || exit 255

MNT=rootfs
SEEK=2047
PKGS="build-essential,openssh-server,sudo,curl,tar,time,less,psmisc,openssl,plymouth,file"
ARCH=$(uname -m)
DIST=bullseye
ROOTFS_NAME=rootfs
USER=user
HOSTNAME=""

while (("$#")); do
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

# Foreign architecture
FOREIGN=false
if [ "$ARCH" != "$(uname -m)" ]; then
    # i386 on an x86_64 host is exempted, as we can run i386 binaries natively
    if [ "$ARCH" != "i386" ] || [ "$(uname -m)" != "x86_64" ]; then
        echo "Requested foreign architecture $ARCH. Grabbing QEMU binfmt handlers..."
        FOREIGN=true

        # Check if binfmt_misc is ready to go
        if [ ! -f /proc/sys/fs/binfmt_misc/register ]; then
            mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc > /dev/null
        fi
        # Reset any qemu handlers...
        find /proc/sys/fs/binfmt_misc -type f -name 'qemu-*' -exec sh -c 'echo -1 > $1' shell {} \; > /dev/null

        # Grab qemu binfmt register script
	if [ ! -f "qemu-binfmt-conf.sh" ]; then
	    wget -q https://raw.githubusercontent.com/qemu/qemu/master/scripts/qemu-binfmt-conf.sh &&
            chmod 777 qemu-binfmt-conf.sh
	fi
        ./qemu-binfmt-conf.sh --qemu-suffix "-static" --qemu-path "/usr/bin" > /dev/null
    fi
fi

if [ $FOREIGN = "true" ]; then
    # Check for according qemu static binary
    if ! which qemu-"$ARCH"-static; then
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
echo "Ensuring clean work environment..."
sudo rm -rf $MNT > /dev/null
sudo mkdir -p $MNT > /dev/null
sudo chmod 0755 $MNT > /dev/null

DEBOOTSTRAP_PARAMS="--arch=$DEBARCH --include=$PKGS --components=main,contrib,non-free $DIST $MNT"
if [ $FOREIGN = "true" ]; then
    DEBOOTSTRAP_PARAMS="--foreign $DEBOOTSTRAP_PARAMS"
fi

# riscv64 is hosted in the debian-ports repository
# debian-ports doesn't include non-free, so we exclude firmware-atheros
if [ "$DEBARCH" == "riscv64" ]; then
    DEBOOTSTRAP_PARAMS="--keyring /usr/share/keyrings/debian-ports-archive-keyring.gpg --exclude firmware-atheros $DEBOOTSTRAP_PARAMS http://deb.debian.org/debian-ports"
fi
echo "Running debootstrap to create base file system..."
eval "sudo debootstrap $DEBOOTSTRAP_PARAMS" > /dev/null

if [ $FOREIGN = "true" ]; then
    echo "Running 2nd stage of debootstrap for non-native architecture \"$ARCH\""
    sudo cp -av "$(which qemu-"$ARCH"-static)" "$MNT$(which qemu-"$ARCH"-static)" > /dev/null
    sudo chroot $MNT /bin/bash -c "/debootstrap/debootstrap --second-stage" > /dev/null
fi

echo "Creating non-root user \"$USER\"..."
PASS=$(perl -e 'print crypt($ARGV[0], "password")' "$USER")
sudo chroot $MNT /bin/bash -c "groupadd -g 1000 $USER && useradd -u 1000 -g 1000 -s /bin/bash -m -p $PASS $USER" > /dev/null

if [ $FOREIGN = "true" ]; then
    rm -rf "$MNT$(which qemu-"$ARCH"-static)" > /dev/null
fi

echo "Configuring usable defaults for root file systems..."
sudo sed -i '/^root/ { s/:x:/::/ }' $MNT/etc/passwd > /dev/null
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $MNT/etc/inittab > /dev/null
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $MNT/etc/network/interfaces > /dev/null
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $MNT/etc/fstab > /dev/null
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $MNT/etc/fstab > /dev/null
# echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $MNT/etc/fstab
# echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $MNT/etc/fstab
if [ $FOREIGN = "false" ]; then
    echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $MNT/etc/fstab > /dev/null
fi
echo -en "127.0.0.1\tlocalhost $ROOTFS_NAME\n" | sudo tee $MNT/etc/hosts > /dev/null
echo "nameserver 8.8.8.8" | sudo tee -a $MNT/etc/resolve.conf > /dev/null
echo "$HOSTNAME" | sudo tee $MNT/etc/hostname > /dev/null
dircolors -p | tee $MNT/home/"$USER"/.dircolors > /dev/null
echo "export TERM=vt100" | tee -a $MNT/home/"$USER"/.bashrc > /dev/null
echo "stty cols 128 rows 192" | tee -a $MNT/home/"$USER"/.bashrc > /dev/null
cp $MNT/home/"$USER"/.bashrc $MNT/home/"$USER"/.dircolors $MNT/root > /dev/null
echo 'eval "$(dircolors ~/.dircolors)" > /dev/null' | tee -a $MNT/root/.bashrc > /dev/null
printf "+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\nWelcome to your LIKE-DBG session :). Happy hacking!\n+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+\n" | tee $MNT/etc/motd > /dev/null
yes | ssh-keygen -f "$ROOTFS_NAME.id_rsa" -t rsa -N '' > /dev/null
sudo mkdir -p $MNT/root/.ssh/ > /dev/null
cat "$ROOTFS_NAME.id_rsa.pub" | sudo tee $MNT/root/.ssh/authorized_keys > /dev/null

echo "Building final disk image and cleaning up..."
dd if=/dev/zero of="$ROOTFS_NAME" bs=1M seek=$SEEK count=1 &> /dev/null
sudo mkfs.ext4 -F "$ROOTFS_NAME" &> /dev/null
sudo mkdir -p /mnt/$MNT > /dev/null
sudo mount -o loop "$ROOTFS_NAME" /mnt/$MNT > /dev/null
sudo cp -a $MNT/. /mnt/$MNT/. > /dev/null
sudo umount /mnt/$MNT > /dev/null
sudo rm -rf "$MNT" > /dev/null
find "$ROOTFS_NAME"* -print0 | xargs -0 chmod 0755 > /dev/null
