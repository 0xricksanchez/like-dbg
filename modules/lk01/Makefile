# lk01 out-of-tree vuln driver. The .ko filename must match this directory's name (lk01/ -> lk01.ko)
# per the modules/ convention; see modules/README.md.
obj-m += lk01.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
