ifneq ($(KERNELRELEASE),)
EXTRA_CFLAGS += -I$(PWD)/../include -DTRUSTEES_DEBUG
obj-m := trustees.o
trustees-objs := security.o fs.o init.o funcs.o

else
ifeq ($(uml),)
KDIR := /lib/modules/`uname -r`/build
ARCH :=
else
KDIR := /home/andy/current-linux
ARCH := 
endif
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) $(ARCH) SUBDIRS=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) $(ARCH) SUBDIRS=$(PWD) modules_install

clean:
	rm -fr *.o *.mod.* *.ko .*o.cmd .tmp_versions
endif
