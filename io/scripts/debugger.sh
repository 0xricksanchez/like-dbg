#!/usr/bin/env bash

PROJECT_DIR=""
VMLINUX=""
ARCH=""
CTF_CTX=0
PATH_GDB_SCRIPT=""
EXT="gef"
USER="user"

while (("$#")); do
	case "$1" in
	-a | --arch)
		# Sets the architecture as expected in GDB
		ARCH=$2
		shift 2
		;;
	-p | --project)
		# Sets the kernel root dir where vmlinux is located
		PROJECT_DIR=$2
		VMLINUX=$PROJECT_DIR/vmlinux
		shift 2
		;;
	-c | --ctf)
		# Sets the CTX context, as we do not need to fix the symlink if we are in a CTF context
		CTF_CTX=$2
		shift 2
		;;
	-g | --gdb_script)
		# Sets the location of the user defined GDB script
		PATH_GDB_SCRIPT=$2
		shift 2
		;;
	-e | --extension)
		# Sets whether we want to use GDB-GEF or PWNDBG
		EXT=$2
		shift 2
		;;
	-u | --user)
		# Sets the docker user
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

if [ -z "$PROJECT_DIR" ] || [ -z "$VMLINUX" ] || [ -z "$ARCH" ] || [ -z "$PATH_GDB_SCRIPT" ]; then
	echo "[!] Not all required arguments were set"
	exit 255
fi

pushd "$HOME" >/dev/null || exit
echo "add-auto-load-safe-path $PROJECT_DIR" >>.gdbinit
if [ "$EXT" == "gef" ]; then
	sed -ir "s/source.*pwndbg.*/# &/" .gdbinit
else
	sed -ir "s/source.*gef.*/# &/" .gdbinit
fi
popd >/dev/null || exit

if [ "$CTF_CTX" -ne 1 ]; then
	sudo rm -f vmlinux-gdb.py
	sudo ln -sd scripts/gdb/vmlinux-gdb.py .
fi

# Handle GDB naming sceme
case "$ARCH" in
arm64)
	ARCH=aarch64
	;;
arm)
	ARCH=armv7
	;;
x86_64)
	ARCH=i386:x86-64:intel
	;;
*) ;;

esac

GDB="gdb-multiarch -q \"$VMLINUX\" -iex \"set architecture $ARCH\" \
    -ex \"add-symbol-file $VMLINUX\""

if [ "$EXT" == "gef" ]; then
	GDB="${GDB} -ex \"gef-remote --qemu-user --qemu-binary $VMLINUX localhost 1234\""
else
	GDB="${GDB} -ex \"target remote :1234\""
fi

GDB="${GDB} -ex \"break start_kernel\" \
    -ex \"continue\" \
    -ex \"lx-symbols\" \
    -ex \"macro define offsetof(_type, _memb) ((long)(&((_type *)0)->_memb))\" \
    -ex \"macro define containerof(_ptr, _type, _memb) ((_type *)((void *)(_ptr) - offsetof(_type, _memb)))\" \
    -x \"$PATH_GDB_SCRIPT\""

if [ "$EXT" == "gef" ]; then
	eval "$GDB"
else
	sudo cp "/home/$USER/.gdbinit" "/root/"
	echo "add-auto-load-safe-path /home/$USER/.gdbinit" | sudo tee -a "/root/.gdbinit"
	GDB="sudo su -c '${GDB}'"
	eval "$GDB"
fi
