ifneq ($(KERNELRELEASE),)
EXTRA_CFLAGS += -I$(PWD)/include -DTRUSTEES_DEBUG
obj-m := trustees.o
trustees-objs := security.o fs.o init.o

else
KDIR := /home/andy/linux-2.6.7 
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) ARCH=um SUBDIRS=$(PWD) modules

clean:
	rm -fr *.o *.mod.* *.ko .*o.cmd .tmp_versions
endif
