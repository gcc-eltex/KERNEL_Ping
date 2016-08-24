KERNELDIR:=/usr/src/linux-headers-$(shell uname -r)
PWD := $(shell pwd)
MODNAME := km_netping
obj-m += $(MODNAME).o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	insmod ./$(MODNAME).ko

remove:
	rmmod $(MODNAME)

clean:
	@rm -rf *.o *.ko *.order *.symvers *.mod.c .$(MODNAME).* .tmp_versions

log:
	dmesg | tail

check:
	./../checkpatch.pl --no-tree -f $(MODNAME).c