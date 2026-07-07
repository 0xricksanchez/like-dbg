# like-dbg out-of-tree module template. Copy this directory, rename `hello.o` to your module's name
# (the .ko filename must match the containing directory's name — see modules/README.md), and point
# `build.custom_modules` (or `--insmod`) at the directory.
obj-m += hello.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
