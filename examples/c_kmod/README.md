# README

This directory houses example kernel modules that can automatically be compiled into a kernel by tweaking your `LIKE_DBG` config:
You can either provide a path to a folder housing a single kernel module such as `examples/c_kmod/ioctl_test_drv/`.
Alternatively, you can provide a path to a folder housing multiple kernel modules as well, e.g.: `examples/c_kmod/`.

```ini
[kernel_builder]
# Provide a path to a parent directory that houses custom kernel modules (see the example)
custom_modules = examples/c_kmod/
```

The above example recursively tries to add all kernel modules found in the given path.
In this scenario, every module located in `examples/c_kmod` you want added to the kernel is to be placed in a proper subdirectory, each with a sound `Makefile` and `Kconfig`.
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
