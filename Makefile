ifneq ($(KERNELRELEASE),)
obj-m := trustees.o
trustees-objs := ts_security.o ts_fs.o trustees.o

else
KDIR := /home/andy/linux-2.6.7 
PWD := $(shell pwd)
CFLAGS := -I./include

default:
	$(MAKE) -C $(KDIR) ARCH=um SUBDIRS=$(PWD) modules

clean:
	rm -f *.o *.mod.* *.ko
endif
