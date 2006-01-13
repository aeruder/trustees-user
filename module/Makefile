ifneq ($(KERNELRELEASE),)
include Kbuild
else
KDIR := /lib/modules/`uname -r`/build
ARCH :=

ifneq ($(ARCH),)
ARCHLINE := ARCH=$(ARCH)
endif

TRUSTEES_PWD := $(shell pwd)
CONFIG_TRUSTEES := m

all::
	$(MAKE) -C $(KDIR) $(ARCHLINE) CONFIG_TRUSTEES=m M=$(TRUSTEES_PWD) modules

install:: all
	$(MAKE) -C $(KDIR) $(ARCHLINE) CONFIG_TRUSTEES=m M=$(TRUSTEES_PWD) modules_install

clean::
	$(MAKE) -C $(KDIR) $(ARCHLINE) CONFIG_TRUSTEES=m M=$(TRUSTEES_PWD) clean

endif
