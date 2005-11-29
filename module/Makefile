ifneq ($(KERNELRELEASE),)
include Kbuild
else
ifeq ($(uml),)
KDIR := /lib/modules/`uname -r`/build
ARCH :=
else
KDIR := /home/andy/current-linux
ARCH :=  
endif

ifeq ($(ARCH),)
ARCHLINE =
else
ARCHLINE = ARCH=$(ARCH)
endif

TRUSTEES_PWD := $(shell pwd)

all::
	$(MAKE) -C $(KDIR) $(ARCHLINE) M=$(TRUSTEES_PWD) modules

install:: all
	$(MAKE) -C $(KDIR) $(ARCHLINE) M=$(TRUSTEES_PWD) modules_install

clean::
	$(MAKE) -C $(KDIR) $(ARCHLINE) M=$(TRUSTEES_PWD) clean

endif
