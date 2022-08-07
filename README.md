# LInux-KErnel DeBuGger (LIKE-DBG) 

**VERY MUCH IN POC/WIP STATE**

This repository aims at automating the boring steps when trying to set up a Linux kernel debugging environment.
All steps from building the kernel to running the kernel and attaching the debugger are transparently done inside docker containers to keep system requirements minimal.
Currently there's a dedicated docker container for every step:

* Building the kernel
* Creating a root file system to use with the earlier build kernel
* A debuggee container that launches QEMU with our custom kernel + rootfs
* A debug container that houses the debugging logic

## Caveats

- [ ] Currently only *x86_64* and *arm64* Linux kernel builds are supported
- [ ] Only recent kernel builds will likely succeed building due to how the requirements for the toolchain differs between versions
- [ ] No android kernel support right now
- [ ] Fine-tuning of GDB environment (e.g. custom breakpoints) missing

## Features

- [x] Automated kernel/root file system builds based on `config.ini`
  - [x] Multi-arch: `x86_64` and `arm64`
  - [x] Kernel compilation modes and custom flag support
  - [x] Building of kernel from *commit id*, *release tag* or *<major>.<minor>.<patch>*-version
  - [x] Applying patch files by specifiying a patch directory in `config.ini`
- [x] GDB + [gef](https://github.com/hugsy/gef) to make debugging fun
- [x] QEMU runtime options for the kernel like `kaslr`, `smep`, `smap`, `kpti`, and others
- [x] Re-using builds/container images across runs to minimize start-up time
- [x] Minimal host system requirements


## Requirements

* `docker` (may work with `podman` as well)
* `tmux`
* `python>=3.7`
    * `venv`

## Configuration

Everything is configured in the `config.ini`
Some fields should not be altered but in general the fields that are of interest to create a custom-tailored kernel debugging environment should be self explanatory.

Once you're set, executing the commands below should drop you into a 3-tile tmux configuration with a booted kernel in QEMU, an attached
GDB debugger, and one terminal for free allocation

```sh
$ tmux
$ python3 -m venv .like-dbg
$ source .like-dbg/bin/activate
$ python3 -m pip install --upgrade pip
$ python3 -m pip install -r requirements.txt
$ python3 start_kgdb.py
```

## Showcase

![img/example.png](img/example.png)
