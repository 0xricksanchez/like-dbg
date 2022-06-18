# standard GDB settings
set disassembly-flavor intel
set pagination off
set print pretty on
set follow-fork-mode child
set history save on
set confirm off

# Arch
source /usr/share/pwndbg/gdbinit.py

# Kernel project specific stuff
add-auto-load-safe-path /project
file /project/vmlinux
# set architecture i386:x86-64:intel
# target remote 127.0.0.1:1234
# lx-symbols
