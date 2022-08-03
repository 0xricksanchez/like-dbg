# LInux-KErnel DeBuGger (LIKE-DBG) - **VERY MUCH IN POC WIP STATE**

This repository aims at automating the boring steps when trying to set up a Linux kernel debugging environment.
All steps from building the kernel to running the kernel and attaching the debugger are transparently done inside docker containers to keep system requirements minimal.

Note: Currently only *x86_64* and *arm64* Linux kernel builds are supported.

## Requirements

Make sure you have `tmux` and `docker` installed. 
If you happen to default to the `clang` compiler make sure you have the complete LLVM toolchain available!

## Setup

In theory, to tweak the environment that you want to debug all you have to do is customize the `config.ini` to your needs.
Afterwards, executing the commands below should drop you into a 3-tile tmux configuration with a QEMU booted kernel, an attached
GDB debugger, and one terminal for free allocation.

```bash
tmux
python3 -m venv .like-dbg
source .like-dbg/bin.activate
python3 ./start_kgdb.py
```

### Tweaking the config

Most of the config fields should be self explanatory.


## Showcase

![img/example.png](img/example.png)
