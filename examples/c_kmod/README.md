# README

This directory houses example kernel modules that can automatically be compiled into a kernel by
tweaking your `LIKE_DBG` config:

```ini
[kernel_builder]
# Provide a path to a parent directory that houses custom kernel modules (see the example)
custom_modules = examples/c_kmod/
```

Every module located in `examples/c_kmod` is to be placed in a proper subdirectory, each with a sound `Makefile` and `Kconfig`.
For example like so:

```bash
$ tree .
.
├── echoservice.c
├── Kconfig
└── Makefile

0 directories, 3 files
```

The kernel builder then tries to add each module into the kernel at compile time.
